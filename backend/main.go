package main

import (
        "context"
        "fmt"
        "net"
        "net/http"
        "os"
        "os/signal"
        "strconv"
        "strings"
        "time"

        gops "github.com/google/gops/agent"
        "github.com/improbable-eng/grpc-web/go/grpcweb"
        "github.com/sirupsen/logrus"
        "golang.org/x/net/http2"
        "golang.org/x/net/http2/h2c"
        "golang.org/x/sys/unix"
        "google.golang.org/grpc"

        "github.com/cilium/hubble-ui/backend/client"
        "github.com/cilium/hubble-ui/backend/internal/config"
        "github.com/cilium/hubble-ui/backend/internal/msg"
        "github.com/cilium/hubble-ui/backend/internal/server/middleware"
        "github.com/cilium/hubble-ui/backend/pkg/logger"
        "github.com/cilium/hubble-ui/backend/proto/ui"
        "github.com/cilium/hubble-ui/backend/server"
)

var (
        log = logger.New("ui-backend")
)

func runServer(cfg *config.Config) {
        // observerAddr := getObserverAddr()
        srv := server.New(cfg, middleware.NewDex(cfg.Dex))

        if err := srv.Run(); err != nil {
                log.Errorf(msg.ServerSetupRunError, err)
                os.Exit(1)
        }

        grpcServer := grpc.NewServer()
        ui.RegisterUIServer(grpcServer, srv)

        wrappedGrpc := grpcweb.WrapServer(
                grpcServer,
                grpcweb.WithOriginFunc(func(origin string) bool {
                        return true
                }),
                grpcweb.WithCorsForRegisteredEndpointsOnly(false),
        )

        // The h2c protocol is the non-TLS version of HTTP/2 which is not available from net/http or golang.org/x/net/http2.
        // https://pkg.go.dev/golang.org/x/net/http2/h2c
        handler := h2c.NewHandler(srv.AuthHandler.AuthMiddleware(func(resp http.ResponseWriter, req *http.Request) {
                log.Infof("handler called on path: %s, with content-type: %s", req.URL.Path, req.Header.Get("Content-Type"))
                if !strings.HasPrefix(req.URL.Path, "/api/") {
                        http.NotFound(resp, req)
                        return
                }
                req.URL.Path = req.URL.Path[len("/api/"):]
                wrappedGrpc.ServeHTTP(resp, req)
        }), &http2.Server{})

        ctx, cancel := signal.NotifyContext(context.Background(), unix.SIGINT, unix.SIGTERM)
        defer cancel()

        addr := cfg.UIServerListenAddr()
        httpSrv := &http.Server{
                Addr:    addr,
                Handler: handler,
                BaseContext: func(net.Listener) context.Context {
                        return ctx
                },
                ReadHeaderTimeout: 5 * time.Second,
        }
        log.Infof(msg.ServerSetupListeningAt, addr)
        if err := httpSrv.ListenAndServe(); err != nil {
                log.Errorf(msg.ServerSetupRunError, err)
                os.Exit(1)
        }
}

func runClient(cfg *config.Config) {
        addr := cfg.UIServerListenAddr()
        log.Infof("connecting to server: %s\n", addr)

        cl := client.New(addr)
        cl.Run()
}

func getMode() string {
        mode, _ := os.LookupEnv("MODE")
        if mode == "client" {
                return "client"
        }

        return "server"
}

func runGops() {
        if enabled, _ := strconv.ParseBool(os.Getenv("GOPS_ENABLED")); !enabled {
                return
        }

        gopsPort := "0"
        if gopsPortEnv := os.Getenv("GOPS_PORT"); gopsPortEnv != "" {
                gopsPort = gopsPortEnv
        }
        // Open socket for using gops to get stacktraces of the agent.
        addr := fmt.Sprintf("127.0.0.1:%s", gopsPort)
        addrField := logrus.Fields{"address": addr}

        if err := gops.Listen(gops.Options{
                Addr:                   addr,
                ReuseSocketAddrAndPort: true,
        }); err != nil {
                log.WithError(err).WithFields(addrField).Fatal("Cannot start gops server")
        }

        log.WithFields(addrField).Info("Started gops server")
}

func main() {
        runGops()

        cfg, err := config.Init()
        if err != nil {
                log.Errorf(msg.ServerSetupConfigInitError, err.Error())
                os.Exit(1)
        }

        if mode := getMode(); mode == "server" {
                runServer(cfg)
        } else {
                runClient(cfg)
        }
}