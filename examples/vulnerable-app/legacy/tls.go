// DELIBERATELY INSECURE demo for ai-security-atlas.
package legacy

import (
	"crypto/md5"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
)

func Setup() (*rsa.PrivateKey, *tls.Config) {
	key, _ := rsa.GenerateKey(rand.Reader, 1024) // PQC004
	_ = md5.New()                                // PQC001
	return key, &tls.Config{MinVersion: tls.VersionTLS10} // PQC005
}
