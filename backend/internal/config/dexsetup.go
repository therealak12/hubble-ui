package config

import (
	"os"
	"time"
)

func setupDex(cfg *Config) {

	dexAddr, ok := os.LookupEnv("DEX_API_ADDR")
	if ok {
		cfg.DexConfig.Addr = dexAddr
	}

	hubbleURL, ok := os.LookupEnv("HUBBLE_URL")
	if ok {
		cfg.DexConfig.HubbleURL = hubbleURL
	}

	dexClientID, ok := os.LookupEnv("DEX_CLIENT_ID")
	if ok {
		cfg.DexConfig.ClientID = dexClientID
	}

	dexSecret, ok := os.LookupEnv("DEX_SECRET")
	if ok {
		cfg.DexConfig.Secret = dexSecret
	}

	dexJWTExpiration, ok := os.LookupEnv("DEX_JWT_EXPIRATION")
	if ok {
		exp, err := time.ParseDuration(dexJWTExpiration)
		if err == nil {
			cfg.DexConfig.JWTExpiration = exp
		}
	}
}
