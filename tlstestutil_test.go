package tlstestutil

import (
	"crypto/x509"
	"testing"
)

func TestTLSTestUtil(t *testing.T) {
	ca, caPool, caKey := CA(t, nil)
	cert := Cert(t, ca, caKey, "fancyHost", nil)
	if _, err := cert.Leaf.Verify(x509.VerifyOptions{DNSName: "fancyHost", Roots: caPool}); err != nil {
		t.Error(err)
	}
}
