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

//go:build requirefips

package tlscommon

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

// fipsVerifyNoneCallback returns a VerifyConnection callback that enforces FIPS
// key-type constraints on all peer certs when chain verification is disabled.
// In non-FIPS builds the stub returns nil so no callback is installed.
func fipsVerifyNoneCallback() func(tls.ConnectionState) error {
	return func(cs tls.ConnectionState) error {
		return checkPeerCertsFIPS(cs.PeerCertificates)
	}
}

// checkAllChainsFIPS rejects if any chain in chains contains a certificate whose
// public key is not FIPS 140-3 approved. cert.Verify() can return multiple chains
// when a certificate has more than one valid path to a trusted root; per SP 800-57
// (weakest-link principle), every authentication path must use only approved keys —
// a non-FIPS chain is unacceptable even when a compliant path also exists.
func checkAllChainsFIPS(chains [][]*x509.Certificate) error {
	for _, chain := range chains {
		if err := checkPeerCertsFIPS(chain); err != nil {
			return err
		}
	}
	return nil
}

// checkPeerCertsFIPS rejects any certificate in certs whose public key is not
// approved by FIPS 140-3. Must be called explicitly from VerifyConnection because
// Go skips its own FIPS certificate check when chain verification is handled by
// the callback rather than the TLS stack (golang/go#80074). Callers pass the
// verified chain when available, or all peer certs when no chain is built.
//
// TODO: once Go exposes a public API for this check (requested in
// https://github.com/golang/go/issues/80074), replace this local copy.
func checkPeerCertsFIPS(certs []*x509.Certificate) error {
	for _, cert := range certs {
		if !isCertAllowedFIPS(cert) {
			return fipsKeyError(cert)
		}
	}
	return nil
}

func fipsKeyError(cert *x509.Certificate) error {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return fmt.Errorf("tls: certificate uses RSA-%d public key which is not allowed by FIPS 140-3 (minimum 2048 bits)", k.N.BitLen())
	case *ecdsa.PublicKey:
		if k.Curve == nil {
			return fmt.Errorf("tls: certificate uses ECDSA public key with unknown curve which is not allowed by FIPS 140-3 (allowed: P-256, P-384, P-521)")
		}
		return fmt.Errorf("tls: certificate uses ECDSA-%s public key which is not allowed by FIPS 140-3 (allowed: P-256, P-384, P-521)", k.Curve.Params().Name)
	default:
		return fmt.Errorf("tls: certificate uses %T public key which is not allowed by FIPS 140-3", cert.PublicKey)
	}
}

// isCertAllowedFIPS reports whether cert uses a FIPS 140-3 approved key:
// RSA ≥ 2048 bits, ECDSA on P-256/P-384/P-521, or Ed25519.
// The ECDSA curve set must stay in sync with the key-exchange allowlist in
// types_fips.go init(). If SP 800-186 changes the approved curves, update both.
// Ed25519 is approved for signatures under FIPS 186-5.
func isCertAllowedFIPS(cert *x509.Certificate) bool {
	switch k := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return k.N.BitLen() >= 2048
	case *ecdsa.PublicKey:
		if k.Curve == nil {
			return false
		}
		// Compare by name rather than pointer to handle non-singleton curve implementations.
		name := k.Curve.Params().Name
		return name == "P-256" || name == "P-384" || name == "P-521"
	case ed25519.PublicKey:
		return true
	default:
		return false
	}
}
