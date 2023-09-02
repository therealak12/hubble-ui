// dexconfig.go
package config

import (
	"time"
)

type Dex struct {
	Addr          string        
	HubbleURL     string        
	ClientID      string       
	Secret        string        // The client secret associated with the ClientID
	JWTExpiration time.Duration // Duration for which the JWT token is valid
}