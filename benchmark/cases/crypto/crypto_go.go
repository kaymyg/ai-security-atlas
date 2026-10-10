// Cryptography in Go.
package cryptocases

import (
	"crypto/des"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/md5"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
)

func BrokenToday(data, key []byte) {
	md5.Sum(data)                          // expect[PQC001]
	sha256.Sum256(data)                    // safe[PQC001]
	rsa.GenerateKey(rand.Reader, 1024)     // expect[PQC004,PQC012]
	_ = &tls.Config{MinVersion: tls.VersionTLS10} // expect[PQC005]
	_ = &tls.Config{MinVersion: tls.VersionTLS13} // safe[PQC005]
	des.NewTripleDESCipher(key)            // expect[PQC002] 3DES via the Go standard library
}

func MigrationInventory(pub *rsa.PublicKey, msg []byte) {
	rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, msg, nil) // expect[PQC010]
	ecdh.P256().GenerateKey(rand.Reader)                      // expect[PQC011]
	ecdsa.GenerateKey(elliptic.P256(), rand.Reader)           // expect[PQC013]
	mlkem.GenerateKey768()                                    // safe[PQC010,PQC011] already post-quantum
}
