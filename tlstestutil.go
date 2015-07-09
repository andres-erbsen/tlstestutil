// Copyright 2014 The Dename Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License"); you may not
// use this file except in compliance with the License. You may obtain a copy of
// the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
// WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
// License for the specific language governing permissions and limitations under
// the License.

// Package tlstestutil provides a simple interface for creating TLS CA and leaf
// certificates for use in tests. This package is not reviewed/maintained for
// security in any sense.
package tlstestutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	_ "crypto/sha256" // for tls
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"io"
	"math/big"
	"net"
	"testing"
	"time"
)

func newSerial(t *testing.T, rnd io.Reader) *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rnd, serialNumberLimit)
	if err != nil {
		t.Fatal(err)
	}
	return serialNumber
}

// CA returns a new CA certificate, a pool containing that certificate, and the
// corresponding private key.
func CA(t *testing.T, rnd io.Reader) (*x509.Certificate, *x509.CertPool, *ecdsa.PrivateKey) {
	if rnd == nil {
		rnd = rand.Reader
	}
	var err error
	caPrivKey, err := ecdsa.GenerateKey(elliptic.P224(), rnd)
	if err != nil {
		t.Fatal(err)
	}
	caCertTemplate := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "testingCA"},
		SerialNumber:          newSerial(t, rnd),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:       true,
		MaxPathLen: 4,
	}
	caCertDER, err := x509.CreateCertificate(rnd, caCertTemplate, caCertTemplate, &caPrivKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatal(err)
	}

	caPool := x509.NewCertPool()
	caPool.AddCert(caCert)
	return caCert, caPool, caPrivKey
}

// Cert generates a new TLS certificate for hostname and signs it using caPrivKey.
func Cert(t *testing.T, caCert *x509.Certificate, caPrivKey *ecdsa.PrivateKey, hostname string, rnd io.Reader) tls.Certificate {
	if rnd == nil {
		rnd = rand.Reader
	}
	privKey, err := ecdsa.GenerateKey(elliptic.P224(), rnd)
	if err != nil {
		t.Fatal(err)
	}
	certTemplate := &x509.Certificate{
		Subject:      pkix.Name{CommonName: hostname},
		SerialNumber: newSerial(t, rnd),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(1 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(hostname); ip != nil {
		certTemplate.IPAddresses = []net.IP{ip}
	}

	certDER, err := x509.CreateCertificate(rnd, certTemplate, caCert, &privKey.PublicKey, caPrivKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{certDER}, PrivateKey: privKey, Leaf: cert}
}
