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

package tlscommon

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
)

// distrustedSPKISHA256 maps the hex SHA-256 of the DER encoded
// SubjectPublicKeyInfo of CA keys that must never be trusted, whatever the
// configured or system root store says, to a human readable name. Matching on
// the key rather than on the certificate also catches every cross-signed copy
// of the same CA.
//
// These are the eight eMudhra intermediate CAs whose private keys were
// disclosed on 2026-10-20 (CVE-2026-111943). They chain to the
// "emSign Root TLS CA - G3" and "emSign Root CS CA - G3" roots and, through
// cross-signs, to Sectigo's "AAA Certificate Services". The roots are not
// listed because they still legitimately issue other certificates.
//
// Go 1.26.10 and 1.27.3 ship the same list in crypto/x509. This copy keeps
// every consumer of tlscommon protected regardless of the toolchain it is
// built with (Go 1.25 never received the fix) and of the CA bundle on the
// host.
//
// Source: https://emudhra.we-have-a-problem.com/impacted-intermediates.json
var distrustedSPKISHA256 = map[string]string{
	"ebed6475c2c2d80fcb199f3fe8dd6e6b3ce60b77eb15d4e42c3dec0c6f5b5105": "EM DV TLS CA - G3B",
	"43bffa19d6ef651451f6841e019931e96f6f2eaeff28ab4b6f1ce4576de2717b": "EM OV TLS CA - G3B",
	"e0254c7fcdc265e2f0f8a428dabb75ab4ae039b4872d62f5ee57f0877d5a8a41": "EM EV TLS CA - G3B",
	"49dd353dc2b919a3770645117d0e60c16115e7d1bc259eefe734b00ea434fe5f": "EM DV TLS CA - G3C",
	"63ecefee431d49523bc1136c4e72d0206a477086caf606cd5cf025686c109cf8": "EM OV TLS CA - G3C",
	"5c0660a2b164910d8ff589c18e14552e9e0ec237dcefe2cb736d41a4811f81a0": "EM EV TLS CA - G3C",
	"ec4ffa1ad0ac88081314b7aaffef6a91f97cd57291bb5ba686c5415f5eb4f6b6": "EM OV CS CA - G3B",
	"92c063d67e8f14db71d288e11266ffdaf69cbf115f7bab14f3bc2f68d25e0e30": "EM OV CS CA - G3C",
}

// ErrDistrustedKey is returned when every verified certificate chain goes
// through a CA whose private key is known to be compromised.
var ErrDistrustedKey = errors.New("certificate chain contains a distrusted CA key")

// distrustedKeyName returns the name of the distrusted CA the public key of
// cert belongs to. The bool is false if the key of cert is not distrusted.
func distrustedKeyName(cert *x509.Certificate) (string, bool) {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	name, found := distrustedSPKISHA256[hex.EncodeToString(sum[:])]
	return name, found
}

// filterDistrustedChains drops every chain that contains a distrusted CA key
// and returns the remaining ones. It runs after the normal chain building, so
// a chain is rejected even when the configured or system root store trusts
// its root.
//
// A peer is accepted as long as one verified chain is free of distrusted keys,
// so a server that also offers a valid path to an unaffected root is not
// rejected. If chains is non-empty and no chain survives, ErrDistrustedKey is
// returned, naming the first distrusted CA found. An empty input is returned
// unchanged: there is nothing to check and the caller decides whether a
// missing chain is acceptable.
func filterDistrustedChains(chains [][]*x509.Certificate) ([][]*x509.Certificate, error) {
	if len(chains) == 0 {
		return chains, nil
	}

	var firstErr error
	clean := chains[:0:0]
	for _, chain := range chains {
		if err := checkChainDistrusted(chain); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		clean = append(clean, chain)
	}

	if len(clean) == 0 {
		return nil, firstErr
	}
	return clean, nil
}

func checkChainDistrusted(chain []*x509.Certificate) error {
	for _, cert := range chain {
		if name, found := distrustedKeyName(cert); found {
			return fmt.Errorf("%w: %q (subject %q)", ErrDistrustedKey, name, cert.Subject)
		}
	}
	return nil
}
