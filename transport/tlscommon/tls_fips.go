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
	"crypto/rsa"
	"crypto/tls"
	"errors"
)

func validateCertificateKeyLength(cert tls.Certificate) error {
	// In FIPS mode, if the key is an RSA key, validate that it is
	// at least 2048 bits long.

	switch typedCert := cert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		if typedCert.PublicKey.N.BitLen() < 2048 {
			return errors.New("certificate is using an RSA key of < 2048 bits")
		}
	}

	return nil
}
