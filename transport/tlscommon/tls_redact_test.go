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
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// midBodyLine returns a line from the middle of a PEM block, i.e. real base64
// content (never a header/footer), so tests can assert it is never leaked.
func midBodyLine(t *testing.T, pemStr string) string {
	t.Helper()
	lines := strings.Split(strings.TrimSpace(pemStr), "\n")
	require.Greater(t, len(lines), 2, "PEM should have a header, body and footer")
	return lines[len(lines)/2]
}

// body returns everything after the first line of a PEM block, so tests can
// replace the "-----BEGIN ...-----" header with a malformed one while keeping
// the real (sensitive) body intact.
func body(pemStr string) string {
	return pemStr[strings.Index(pemStr, "\n")+1:]
}

// TestLoadCertificateDoesNotLeakPEM a malformed
// inline PEM (a private key in particular) must never appear in the error
// returned by LoadCertificate. The internal log.Errorf calls use the very same
// inputs (pemSource(...) and err), so a clean returned error implies a clean
// log line too.
func TestLoadCertificateDoesNotLeakPEM(t *testing.T) {
	keyPEM, certPEM := makeKeyCertPair(t, blockTypePKCS8, "")

	tests := []struct {
		name string
		// mutate returns the cert/key pair to feed LoadCertificate and the
		// sensitive line that must not appear in the error.
		certificate string
		key         string
		secret      string
	}{
		{
			name:        "malformed key, header keeps leading dashes",
			certificate: certPEM,
			key:         "-----asdasd-----\n" + body(keyPEM),
			secret:      midBodyLine(t, keyPEM),
		},
		{
			name:        "malformed key, header without leading dashes",
			certificate: certPEM,
			key:         "asdasd-----\n" + body(keyPEM),
			secret:      midBodyLine(t, keyPEM),
		},
		{
			name:        "malformed cert, header keeps leading dashes",
			certificate: "-----asdasd-----\n" + body(certPEM),
			key:         keyPEM,
			secret:      midBodyLine(t, certPEM),
		},
		{
			name:        "malformed cert, header without leading dashes",
			certificate: "asdasd-----\n" + body(certPEM),
			key:         keyPEM,
			secret:      midBodyLine(t, certPEM),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := LoadCertificate(&CertificateConfig{
				Certificate: tc.certificate,
				Key:         tc.key,
			})
			require.Error(t, err)

			msg := err.Error()
			assert.NotContains(t, msg, tc.secret,
				"error leaks PEM body material:\n%s", msg)
			assert.NotContains(t, msg, "PRIVATE KEY",
				"error leaks a PEM private-key block:\n%s", msg)
			assert.NotContains(t, msg, "BEGIN",
				"error leaks PEM block content:\n%s", msg)
			assert.Contains(t, msg, "PEM REDACTED",
				"error should label the inline source as redacted")
		})
	}
}

// TestLoadCertificateAuthoritiesDoesNotLeakPEM is the LoadCertificateAuthorities
// counterpart to TestLoadCertificateDoesNotLeakPEM: a malformed inline CA must
// never appear in the errors returned.
func TestLoadCertificateAuthoritiesDoesNotLeakPEM(t *testing.T) {
	_, certPEM := makeKeyCertPair(t, blockTypePKCS8, "")

	tests := []struct {
		name string
		ca   string
	}{
		{
			name: "malformed CA, header keeps leading dashes",
			ca:   "-----asdasd-----\n" + body(certPEM),
		},
		{
			name: "malformed CA, header without leading dashes",
			ca:   "asdasd-----\n" + body(certPEM),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			secret := midBodyLine(t, certPEM)

			_, errs := LoadCertificateAuthorities([]string{tc.ca})
			require.NotEmpty(t, errs)

			for _, err := range errs {
				msg := err.Error()
				assert.NotContains(t, msg, secret,
					"error leaks PEM body material:\n%s", msg)
				assert.NotContains(t, msg, "BEGIN",
					"error leaks PEM block content:\n%s", msg)
				assert.Contains(t, msg, "PEM REDACTED",
					"error should label the inline source as redacted")
			}
		})
	}
}

// TestLoadCertificateValidInlinePEM is a regression guard: a well-formed inline
// PEM pair must still load successfully after the redaction changes.
func TestLoadCertificateValidInlinePEM(t *testing.T) {
	keyPEM, certPEM := makeKeyCertPair(t, blockTypePKCS8, "")

	cert, err := LoadCertificate(&CertificateConfig{Certificate: certPEM, Key: keyPEM})
	require.NoError(t, err)
	require.NotNil(t, cert)
	assert.NotEmpty(t, cert.Certificate)
}

// TestLoadCertificateMissingFileShowsPath is a regression guard: a genuine
// (single-line) file path that does not exist must still be reported verbatim
// so users can fix it — only inline content is redacted.
func TestLoadCertificateMissingFileShowsPath(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist.pem")

	_, err := LoadCertificate(&CertificateConfig{Certificate: missing, Key: missing})
	require.Error(t, err)
	assert.Contains(t, err.Error(), missing, "missing file path should be visible")
	assert.NotContains(t, err.Error(), "PEM REDACTED", "a real path must not be redacted")
}

func TestIsInlinePEM(t *testing.T) {
	keyPEM, certPEM := makeKeyCertPair(t, blockTypePKCS8, "")

	tests := map[string]struct {
		in   string
		want bool
	}{
		"valid inline cert":                              {certPEM, true},
		"valid inline key":                               {keyPEM, true},
		"malformed, leading dashes":                      {"-----asdasd-----\n" + body(keyPEM), true},
		"malformed, multiline no dashes":                 {"asdasd-----\n" + body(keyPEM), true},
		"single line with PEM armor":                     {"asdasd-----MIIE-----END PRIVATE KEY-----", true},
		"unix file path":                                 {"/etc/pki/tls/key.pem", false},
		"windows file path":                              {`C:\pki\key.pem`, false},
		"relative file path":                             {"certs/key.pem", false},
		"empty string":                                   {"", false},
		"path with trailing newline (YAML block scalar)": {"/etc/pki/tls/key.pem\n", false},
		"path with surrounding whitespace":               {"  /etc/pki/tls/key.pem  \n", false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			assert.Equal(t, tc.want, isInlinePEM(tc.in))
		})
	}
}

func TestPemSource(t *testing.T) {
	keyPEM, _ := makeKeyCertPair(t, blockTypePKCS8, "")

	assert.Equal(t, "PEM REDACTED", pemSource(keyPEM))
	assert.Equal(t, "PEM REDACTED", pemSource("asdasd-----\nbody\n-----END PRIVATE KEY-----"))
	assert.Equal(t, "/etc/pki/key.pem", pemSource("/etc/pki/key.pem"))
	assert.Equal(t, "/etc/pki/key.pem\n", pemSource("/etc/pki/key.pem\n"),
		"a path with a trailing newline (e.g. YAML block scalar) must not be redacted")
}

// TestLoadCertificatePathWithTrailingNewlineIsNotRedacted a genuine file path
// with trailing whitespace/newline (as produced by a YAML block scalar like
// `cert: |`) must still be classified and reported as a path rather than
// misclassified as inline PEM content and redacted. The trailing newline is
// still part of the path handed to os.Open, so the file is not found either
// way -- this only guards that the real path stays visible in the resulting
// error rather than being swapped for a fabricated "PEM REDACTED". The OS
// error text for an invalid path differs by platform (e.g. Windows rejects
// an embedded newline outright instead of reporting "no such file"), so the
// assertion checks for the path substring rather than any particular error
// string.
func TestLoadCertificatePathWithTrailingNewlineIsNotRedacted(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := writeKeyAndCertFiles(t, dir)

	_, err := LoadCertificate(&CertificateConfig{
		Certificate: certPath + "\n",
		Key:         keyPath + "\n",
	})
	require.Error(t, err)
	assert.NotContains(t, err.Error(), "PEM REDACTED",
		"a file path must not be redacted just because it has a trailing newline")
	assert.Contains(t, err.Error(), certPath,
		"the real path should still be visible in the error, proving it was attempted via os.Open rather than treated as inline content")
}
