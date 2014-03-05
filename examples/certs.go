package examples

import (
	"crypto/x509/pkix"
	"os"

	"launchpad.net/gocert"
)

// BuildCerts creates self-signed TLS certificates for the demos to
// save you the trouble.
func BuildCerts(keyFile string, certFile string, cname string) error {
	if _, err := os.Stat(keyFile); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		_, err = gocert.CreateKey(keyFile, nil)
		if err != nil {
			return err
		}
	}
	if _, err := os.Stat(certFile); err != nil {
		if !os.IsNotExist(err) {
			return err
		}
		err = gocert.CreateSelfSigned(&pkix.Name{CommonName: cname}, certFile, keyFile, nil)
		if err != nil {
			return err
		}
	}
	return nil
}
