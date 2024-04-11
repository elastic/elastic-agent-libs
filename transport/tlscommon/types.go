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
	"crypto/tls"
	"errors"
	"fmt"
)

var (
	// ErrNotACertificate indicates a PEM file to be loaded not being a valid
	// PEM file or certificate.
	ErrNotACertificate = errors.New("file is not a certificate")

	// ErrCertificateNoKey indicate a configuration error with missing key file
	ErrKeyUnspecified = errors.New("key file not configured")

	// ErrKeyNoCertificate indicate a configuration error with missing certificate file
	ErrCertificateUnspecified = errors.New("certificate file not configured")
)

var tlsCipherSuites = map[string]CipherSuite{
	// ECDHE-ECDSA
	"ECDHE-ECDSA-AES-128-CBC-SHA":    CipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA),
	"ECDHE-ECDSA-AES-128-CBC-SHA256": CipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256),
	"ECDHE-ECDSA-AES-128-GCM-SHA256": CipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256),
	"ECDHE-ECDSA-AES-256-CBC-SHA":    CipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA),
	"ECDHE-ECDSA-AES-256-GCM-SHA384": CipherSuite(tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384),
	"ECDHE-ECDSA-CHACHA20-POLY1305":  CipherSuite(tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305),
	"ECDHE-ECDSA-RC4-128-SHA":        CipherSuite(tls.TLS_ECDHE_ECDSA_WITH_RC4_128_SHA),

	// ECDHE-RSA
	"ECDHE-RSA-3DES-CBC3-SHA":      CipherSuite(tls.TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA),
	"ECDHE-RSA-AES-128-CBC-SHA":    CipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA),
	"ECDHE-RSA-AES-128-CBC-SHA256": CipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256),
	"ECDHE-RSA-AES-128-GCM-SHA256": CipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256),
	"ECDHE-RSA-AES-256-CBC-SHA":    CipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA),
	"ECDHE-RSA-AES-256-GCM-SHA384": CipherSuite(tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384),
	"ECDHE-RSA-CHACHA20-POLY1205":  CipherSuite(tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305),
	"ECDHE-RSA-RC4-128-SHA":        CipherSuite(tls.TLS_ECDHE_RSA_WITH_RC4_128_SHA),

	// RSA-X
	"RSA-RC4-128-SHA":   CipherSuite(tls.TLS_RSA_WITH_RC4_128_SHA),
	"RSA-3DES-CBC3-SHA": CipherSuite(tls.TLS_RSA_WITH_3DES_EDE_CBC_SHA),

	// RSA-AES
	"RSA-AES-128-CBC-SHA":    CipherSuite(tls.TLS_RSA_WITH_AES_128_CBC_SHA),
	"RSA-AES-128-CBC-SHA256": CipherSuite(tls.TLS_RSA_WITH_AES_128_CBC_SHA256),
	"RSA-AES-128-GCM-SHA256": CipherSuite(tls.TLS_RSA_WITH_AES_128_GCM_SHA256),
	"RSA-AES-256-CBC-SHA":    CipherSuite(tls.TLS_RSA_WITH_AES_256_CBC_SHA),
	"RSA-AES-256-GCM-SHA384": CipherSuite(tls.TLS_RSA_WITH_AES_256_GCM_SHA384),

	"TLS-AES-128-GCM-SHA256":       CipherSuite(tls.TLS_AES_128_GCM_SHA256),
	"TLS-AES-256-GCM-SHA384":       CipherSuite(tls.TLS_AES_256_GCM_SHA384),
	"TLS-CHACHA20-POLY1305-SHA256": CipherSuite(tls.TLS_CHACHA20_POLY1305_SHA256),
}

var tlsCipherSuitesInverse = make(map[CipherSuite]string, len(tlsCipherSuites))
var tlsRenegotiationSupportTypesInverse = make(map[TLSRenegotiationSupport]string, len(tlsRenegotiationSupportTypes))
var tlsVerificationModesInverse = make(map[TLSVerificationMode]string, len(tlsVerificationModes))
var tlsClientAuthTypesInverse = make(map[TLSClientAuth]string, len(tlsClientAuthTypes))

// Init creates a inverse representation of the values mapping.
func init() {
	for cipherName, i := range tlsCipherSuites {
		tlsCipherSuitesInverse[i] = cipherName
	}

	for name, t := range tlsRenegotiationSupportTypes {
		tlsRenegotiationSupportTypesInverse[t] = name
	}

	for name, t := range tlsVerificationModes {
		tlsVerificationModesInverse[t] = name
	}

	for name, t := range tlsClientAuthTypes {
		tlsClientAuthTypesInverse[t] = name
	}
}

var tlsCurveTypes = map[string]tlsCurveType{
	"P-256":  tlsCurveType(tls.CurveP256),
	"P-384":  tlsCurveType(tls.CurveP384),
	"P-521":  tlsCurveType(tls.CurveP521),
	"X25519": tlsCurveType(tls.X25519),
}

var tlsRenegotiationSupportTypes = map[string]TLSRenegotiationSupport{
	"never":  TLSRenegotiationSupport(tls.RenegotiateNever),
	"once":   TLSRenegotiationSupport(tls.RenegotiateOnceAsClient),
	"freely": TLSRenegotiationSupport(tls.RenegotiateFreelyAsClient),
}

type TLSClientAuth int

const (
	TLSClientAuthNone     TLSClientAuth = TLSClientAuth(tls.NoClientCert)
	TLSClientAuthOptional               = TLSClientAuth(tls.VerifyClientCertIfGiven)
	TLSClientAuthRequired               = TLSClientAuth(tls.RequireAndVerifyClientCert)

	unknownType = "unknown"
)

var tlsClientAuthTypes = map[string]TLSClientAuth{
	"none":     TLSClientAuthNone,
	"optional": TLSClientAuthOptional,
	"required": TLSClientAuthRequired,
}

// TLSVerificationMode represents the type of verification to do on the remote host:
// `none`, `certificate`, and `full` and we default to `full`.
// Internally this option is transformed into the `insecure` field in the `tls.Config` struct.
type TLSVerificationMode uint8

// Constants of the supported verification mode.
const (
	VerifyFull TLSVerificationMode = iota
	VerifyNone
	VerifyCertificate
	VerifyStrict
)

var tlsVerificationModes = map[string]TLSVerificationMode{
	"full":        VerifyFull,
	"strict":      VerifyStrict,
	"none":        VerifyNone,
	"certificate": VerifyCertificate,
}

func (m TLSVerificationMode) String() string {
	if s, ok := tlsVerificationModesInverse[m]; ok {
		return s
	}
	return unknownType
}

// MarshalText marshal the verification mode into a human readable value.
func (m TLSVerificationMode) MarshalText() ([]byte, error) {
	if s, ok := tlsVerificationModesInverse[m]; ok {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("could not marshal '%+v' to text", m)
}

// Unpack unpacks the input into a TLSVerificationMode.
func (m *TLSVerificationMode) Unpack(in interface{}) error {
	if in == nil {
		*m = VerifyFull
		return nil
	}
	switch o := in.(type) {
	case string:
		if o == "" {
			*m = VerifyFull
			return nil
		}

		mode, found := tlsVerificationModes[o]
		if !found {
			return fmt.Errorf("unknown verification mode '%v'", o)
		}
		*m = mode
	case uint64:
		*m = TLSVerificationMode(o)
	default:
		return fmt.Errorf("verification mode is an unknown type: %T", o)
	}
	return nil
}

func (m *TLSVerificationMode) Validate() error {
	if *m > VerifyStrict {
		return fmt.Errorf("unsupported verification mode: %v", m)
	}
	return nil
}

func (m TLSClientAuth) String() string {
	if s, ok := tlsClientAuthTypesInverse[m]; ok {
		return s
	}
	return unknownType
}

func (m TLSClientAuth) MarshalText() ([]byte, error) {
	if s, ok := tlsClientAuthTypesInverse[m]; ok {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("could not marshal '%+v' to text", m)
}

func (m *TLSClientAuth) Unpack(in interface{}) error {
	if in == nil {
		*m = TLSClientAuthNone
		return nil
	}
	switch o := in.(type) {
	case string:
		if o == "" {
			*m = TLSClientAuthNone
			return nil
		}
		mode, found := tlsClientAuthTypes[o]
		if !found {
			return fmt.Errorf("unknown client authentication mode '%v'", o)
		}

		*m = mode
	case uint64:
		*m = TLSClientAuth(o)
	case int64: // underlying type is int so we need both uint64 and int64 as options for TLSClientAuth
		*m = TLSClientAuth(o)
	default:
		return fmt.Errorf("client auth mode is an unknown type: %T", o)
	}
	return nil
}

type CipherSuite uint16

func (cs *CipherSuite) Unpack(i interface{}) error {
	switch o := i.(type) {
	case string:
		suite, found := tlsCipherSuites[o]
		if !found {
			return fmt.Errorf("invalid tls cipher suite '%v'", o)
		}

		*cs = suite
	case uint64:
		*cs = CipherSuite(o)
	default:
		return fmt.Errorf("cipher suite is an unknown type: %T", o)
	}
	return nil
}

func (cs CipherSuite) String() string {
	if s, found := tlsCipherSuitesInverse[cs]; found {
		return s
	}
	return unknownType
}

type tlsCurveType tls.CurveID

func (ct *tlsCurveType) Unpack(i interface{}) error {
	switch o := i.(type) {
	case string:
		t, found := tlsCurveTypes[o]
		if !found {
			return fmt.Errorf("invalid tls curve type '%v'", o)
		}

		*ct = t
	case uint64:
		*ct = tlsCurveType(o)
	default:
		return fmt.Errorf("tls curve type is an unsupported input type: %T", o)
	}
	return nil
}

type TLSRenegotiationSupport tls.RenegotiationSupport

func (r TLSRenegotiationSupport) String() string {
	if t, found := tlsRenegotiationSupportTypesInverse[r]; found {
		return t
	}
	return "<" + unknownType + ">"
}

func (r *TLSRenegotiationSupport) Unpack(i interface{}) error {
	switch o := i.(type) {
	case string:
		t, found := tlsRenegotiationSupportTypes[o]
		if !found {
			return fmt.Errorf("invalid tls renegotiation type '%v'", o)
		}

		*r = t
	case uint64:
		*r = TLSRenegotiationSupport(o)
	default:
		return fmt.Errorf("tls renegotation support is an unknown type: %T", o)
	}
	return nil
}

func (r TLSRenegotiationSupport) MarshalText() ([]byte, error) {
	if t, found := tlsRenegotiationSupportTypesInverse[r]; found {
		return []byte(t), nil
	}

	return nil, fmt.Errorf("could not marshal '%+v' to text", r)
}

func (r TLSRenegotiationSupport) MarshalYAML() (interface{}, error) {
	if t, found := tlsRenegotiationSupportTypesInverse[r]; found {
		return t, nil
	}

	return nil, fmt.Errorf("could not marshal '%+v' to text", r)
}

// CertificateConfig define a common set of fields for a certificate.
type CertificateConfig struct {
	Certificate    string `config:"certificate" yaml:"certificate,omitempty"`
	Key            string `config:"key" yaml:"key,omitempty"`
	Passphrase     string `config:"key_passphrase" yaml:"key_passphrase,omitempty"`
	PassphrasePath string `config:"key_passphrase_path" yaml:"key_passphrase_path,omitempty"`
}

// Validate validates the CertificateConfig
func (c *CertificateConfig) Validate() error {
	hasCertificate := c.Certificate != ""
	hasKey := c.Key != ""

	switch {
	case hasCertificate && !hasKey:
		return ErrKeyUnspecified
	case !hasCertificate && hasKey:
		return ErrCertificateUnspecified
	}
	return nil
}

func convCipherSuites(suites []CipherSuite) []uint16 {
	if len(suites) == 0 {
		return nil
	}
	cipherSuites := make([]uint16, len(suites))
	for i, s := range suites {
		cipherSuites[i] = uint16(s)
	}
	return cipherSuites
}
