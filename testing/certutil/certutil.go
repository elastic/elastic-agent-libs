// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package certutil

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"time"
)

// Pair is a certificate and its private key in PEM format.
type Pair struct {
	Cert []byte
	Key  []byte
}

// NewRootCA generates a new x509 Certificate and returns:
// - the private key
// - the certificate
// - the certificate in PEM format as a byte slice.
//
// If any error occurs during the generation process, a non-nil error is returned.
func NewRootCA() (*ecdsa.PrivateKey, *x509.Certificate, Pair, error) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("could not create private key: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(3 * time.Hour)

	rootTemplate := x509.Certificate{
		DNSNames:     []string{"localhost"},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		SerialNumber: big.NewInt(1653),
		Subject: pkix.Name{
			Organization: []string{"Gallifrey"},
			CommonName:   "localhost",
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	rootCertRawBytes, err := x509.CreateCertificate(
		rand.Reader, &rootTemplate, &rootTemplate, &rootKey.PublicKey, rootKey)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("could not create CA: %w", err)
	}

	rootPrivKeyDER, err := x509.MarshalECPrivateKey(rootKey)
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("could not marshal private key: %w", err)
	}

	// PEM private key
	var rootPrivBytesOut []byte
	rootPrivateKeyBuff := bytes.NewBuffer(rootPrivBytesOut)
	err = pem.Encode(rootPrivateKeyBuff, &pem.Block{
		Type: "EC PRIVATE KEY", Bytes: rootPrivKeyDER})
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("could not pem.Encode private key: %w", err)
	}

	// PEM certificate
	var rootCertBytesOut []byte
	rootCertPemBuff := bytes.NewBuffer(rootCertBytesOut)
	err = pem.Encode(rootCertPemBuff, &pem.Block{
		Type: "CERTIFICATE", Bytes: rootCertRawBytes})
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("could not pem.Encode certificate: %w", err)
	}

	// tls.Certificate
	rootTLSCert, err := tls.X509KeyPair(
		rootCertPemBuff.Bytes(), rootPrivateKeyBuff.Bytes())
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("could not create key pair: %w", err)
	}

	rootCACert, err := x509.ParseCertificate(rootTLSCert.Certificate[0])
	if err != nil {
		return nil, nil, Pair{}, fmt.Errorf("could not parse certificate: %w", err)
	}

	return rootKey, rootCACert, Pair{
		Cert: rootCertPemBuff.Bytes(),
		Key:  rootPrivateKeyBuff.Bytes(),
	}, nil
}

// GenerateChildCert generates a x509 Certificate as a child of caCert and
// returns the following:
// - the certificate in PEM format as a byte slice
// - the private key in PEM format as a byte slice
// - the certificate and private key as a tls.Certificate
//
// If any error occurs during the generation process, a non-nil error is returned.
func GenerateChildCert(name string, ips []net.IP, caPrivKey crypto.PrivateKey, caCert *x509.Certificate) (*tls.Certificate, Pair, error) {

	notBefore := time.Now()
	notAfter := notBefore.Add(3 * time.Hour)

	certTemplate := &x509.Certificate{
		DNSNames:     []string{name},
		IPAddresses:  ips,
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			Organization: []string{"Gallifrey"},
			CommonName:   name,
		},
		NotBefore: notBefore,
		NotAfter:  notAfter,
		KeyUsage:  x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
	}

	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, Pair{}, fmt.Errorf("could not create private key: %w", err)
	}

	certRawBytes, err := x509.CreateCertificate(
		rand.Reader, certTemplate, caCert, &privateKey.PublicKey, caPrivKey)
	if err != nil {
		return nil, Pair{}, fmt.Errorf("could not create CA: %w", err)
	}

	privateKeyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, Pair{}, fmt.Errorf("could not marshal private key: %w", err)
	}

	// PEM private key
	var privBytesOut []byte
	privateKeyBuff := bytes.NewBuffer(privBytesOut)
	err = pem.Encode(privateKeyBuff, &pem.Block{
		Type: "EC PRIVATE KEY", Bytes: privateKeyDER})
	if err != nil {
		return nil, Pair{}, fmt.Errorf("could not pem.Encode private key: %w", err)
	}
	privateKeyPemBytes := privateKeyBuff.Bytes()

	// PEM certificate
	var certBytesOut []byte
	certBuff := bytes.NewBuffer(certBytesOut)
	err = pem.Encode(certBuff, &pem.Block{
		Type: "CERTIFICATE", Bytes: certRawBytes})
	if err != nil {
		return nil, Pair{}, fmt.Errorf("could not pem.Encode certificate: %w", err)
	}
	certPemBytes := certBuff.Bytes()

	// TLS Certificate
	tlsCert, err := tls.X509KeyPair(certPemBytes, privateKeyPemBytes)
	if err != nil {
		return nil, Pair{}, fmt.Errorf("could not create key pair: %w", err)
	}

	return &tlsCert, Pair{
		Cert: certPemBytes,
		Key:  privateKeyPemBytes,
	}, nil
}

// NewRootAndChildCerts returns a root CA and a child certificate and their keys
// for "localhost" and "127.0.0.1".
func NewRootAndChildCerts() (Pair, Pair, error) {
	rootKey, rootCACert, rootPair, err := NewRootCA()
	if err != nil {
		return Pair{}, Pair{}, fmt.Errorf("could not generate root CA: %w", err)
	}

	_, childPair, err :=
		GenerateChildCert(
			"localhost",
			[]net.IP{net.ParseIP("127.0.0.1")},
			rootKey,
			rootCACert)
	if err != nil {
		return Pair{}, Pair{}, fmt.Errorf(
			"could not generate child TLS certificate CA: %w", err)
	}

	return rootPair, childPair, nil
}
