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
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/testing/certutil"
)

// These benchmarks quantify the memory/allocation impact of the
// CertReloader/CAReloader hot-reload machinery (added in #404, #412, #417,
// #419) relative to the static, load-once-and-hold behavior that preceded
// it. They're meant to answer two concrete questions:
//
//  1. How much extra memory does enabling reload add per configured TLS
//     endpoint (i.e. per Config/ServerConfig, not per connection)?
//  2. Does the cost scale with the number of TLS handshakes/connections
//     served by an already-loaded config, or only with the number of
//     distinct configs and the reload interval?
//
// genCAFile and genCertKeyFiles are benchmark-only equivalents of the
// writeCAFile/writeKeyAndCertFiles helpers used by the non-benchmark tests
// in this package; those take a *testing.T, so they can't be reused from a
// *testing.B.

func genCAFile(dir, name string) (string, error) {
	_, _, pair, err := certutil.NewRootCA()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, pair.Cert, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func genCertKeyFiles(dir string) (certPath, keyPath string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	tml := x509.Certificate{
		SerialNumber: new(big.Int),
		Subject:      pkix.Name{CommonName: "bench"},
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &tml, &tml, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		return "", "", err
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		return "", "", err
	}
	return certPath, keyPath, nil
}

// BenchmarkCertLoad isolates the marginal cost of wrapping a loaded
// certificate in a CertReloader versus the pre-reload behavior of loading it
// once into a bare *tls.Certificate. Both subtests re-read and re-parse the
// same files on every iteration, so the delta between them is the
// CertReloader struct itself (mutex, logger, path strings, timestamp) - not
// the underlying certificate data, which is the same size either way.
func BenchmarkCertLoad(b *testing.B) {
	dir := b.TempDir()
	certPath, keyPath, err := genCertKeyFiles(dir)
	if err != nil {
		b.Fatalf("generating cert/key: %v", err)
	}

	b.Run("StaticNoReload", func(b *testing.B) {
		cfg := &CertificateConfig{Certificate: certPath, Key: keyPath}
		b.ReportAllocs()
		var sink *tls.Certificate
		for i := 0; i < b.N; i++ {
			cert, err := LoadCertificate(cfg)
			if err != nil {
				b.Fatal(err)
			}
			sink = cert
		}
		runtime.KeepAlive(sink)
	})

	b.Run("CertReloader", func(b *testing.B) {
		b.ReportAllocs()
		var sink *CertReloader
		for i := 0; i < b.N; i++ {
			r, err := NewCertReloader(certPath, keyPath)
			if err != nil {
				b.Fatal(err)
			}
			sink = r
		}
		runtime.KeepAlive(sink)
	})
}

// BenchmarkCAPoolLoad is the CAReloader equivalent of BenchmarkCertLoad.
func BenchmarkCAPoolLoad(b *testing.B) {
	dir := b.TempDir()
	caPath, err := genCAFile(dir, "ca.pem")
	if err != nil {
		b.Fatalf("generating CA: %v", err)
	}
	caPaths := []string{caPath}

	b.Run("StaticNoReload", func(b *testing.B) {
		b.ReportAllocs()
		var sink *staticCertPool
		for i := 0; i < b.N; i++ {
			pool, errs := LoadCertificateAuthorities(caPaths)
			if len(errs) > 0 {
				b.Fatal(errs)
			}
			sink = newStaticCertPool(pool)
		}
		runtime.KeepAlive(sink)
	})

	b.Run("CAReloader", func(b *testing.B) {
		b.ReportAllocs()
		var sink *CAReloader
		for i := 0; i < b.N; i++ {
			r, err := NewCAReloader(caPaths, time.Hour)
			if err != nil {
				b.Fatal(err)
			}
			sink = r
		}
		runtime.KeepAlive(sink)
	})
}

// BenchmarkLoadTLSConfig measures the end-to-end cost of LoadTLSConfig - the
// function every TLS-enabled client config actually goes through - with
// certificate_reload on versus off. This is the realistic "per configured
// endpoint" cost, combining both the cert and CA paths.
func BenchmarkLoadTLSConfig(b *testing.B) {
	dir := b.TempDir()
	caPath, err := genCAFile(dir, "ca.pem")
	if err != nil {
		b.Fatalf("generating CA: %v", err)
	}
	certPath, keyPath, err := genCertKeyFiles(dir)
	if err != nil {
		b.Fatalf("generating cert/key: %v", err)
	}
	logger := logp.NewLogger("bench")

	disabled, enabled := false, true

	b.Run("ReloadDisabled", func(b *testing.B) {
		cfg := &Config{
			CAs:               []string{caPath},
			Certificate:       CertificateConfig{Certificate: certPath, Key: keyPath},
			CertificateReload: CertificateReload{Enabled: &disabled},
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := LoadTLSConfig(cfg, logger); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ReloadEnabled", func(b *testing.B) {
		cfg := &Config{
			CAs:               []string{caPath},
			Certificate:       CertificateConfig{Certificate: certPath, Key: keyPath},
			CertificateReload: CertificateReload{Enabled: &enabled, ReloadInterval: time.Hour},
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := LoadTLSConfig(cfg, logger); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkLoadTLSServerConfig is the server-side (LoadTLSServerConfig)
// equivalent of BenchmarkLoadTLSConfig.
func BenchmarkLoadTLSServerConfig(b *testing.B) {
	dir := b.TempDir()
	caPath, err := genCAFile(dir, "ca.pem")
	if err != nil {
		b.Fatalf("generating CA: %v", err)
	}
	certPath, keyPath, err := genCertKeyFiles(dir)
	if err != nil {
		b.Fatalf("generating cert/key: %v", err)
	}
	logger := logp.NewLogger("bench")

	disabled, enabled := false, true

	b.Run("ReloadDisabled", func(b *testing.B) {
		cfg := &ServerConfig{
			CAs:               []string{caPath},
			Certificate:       CertificateConfig{Certificate: certPath, Key: keyPath},
			CertificateReload: CertificateReload{Enabled: &disabled},
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := LoadTLSServerConfig(cfg, logger); err != nil {
				b.Fatal(err)
			}
		}
	})

	b.Run("ReloadEnabled", func(b *testing.B) {
		cfg := &ServerConfig{
			CAs:               []string{caPath},
			Certificate:       CertificateConfig{Certificate: certPath, Key: keyPath},
			CertificateReload: CertificateReload{Enabled: &enabled, ReloadInterval: time.Hour},
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			if _, err := LoadTLSServerConfig(cfg, logger); err != nil {
				b.Fatal(err)
			}
		}
	})
}

// BenchmarkCertReloader_GetCertificate_WithinInterval simulates many TLS
// handshakes/connections (b.N of them) served by a single, already-loaded
// CertReloader whose reload interval never elapses. If reloader instances
// "accumulated" with connection volume, allocs/op here would grow with b.N;
// instead it should stay flat (an RLock + pointer read), showing that
// connection/handshake volume does not drive memory growth - only the
// number of distinct configured endpoints does.
func BenchmarkCertReloader_GetCertificate_WithinInterval(b *testing.B) {
	dir := b.TempDir()
	certPath, keyPath, err := genCertKeyFiles(dir)
	if err != nil {
		b.Fatalf("generating cert/key: %v", err)
	}
	r, err := NewCertReloader(certPath, keyPath, WithReloadInterval(time.Hour))
	if err != nil {
		b.Fatalf("creating cert reloader: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := r.GetCertificate(nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCAReloader_GetCertPool_WithinInterval is the CAReloader
// equivalent of BenchmarkCertReloader_GetCertificate_WithinInterval.
func BenchmarkCAReloader_GetCertPool_WithinInterval(b *testing.B) {
	dir := b.TempDir()
	caPath, err := genCAFile(dir, "ca.pem")
	if err != nil {
		b.Fatalf("generating CA: %v", err)
	}
	r, err := NewCAReloader([]string{caPath}, time.Hour)
	if err != nil {
		b.Fatalf("creating CA reloader: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = r.GetCertPool()
	}
}

// BenchmarkCertReloader_GetCertificate_ReloadEveryCall forces a real
// disk-read-and-reparse on every call (reload interval effectively zero).
// This is the worst-case steady-state cost of the reload feature: unlike the
// hot-path benchmarks above, it scales with the number of distinct reloader
// instances times how often each one actually reloads (1/reload_interval),
// never with connection/handshake count.
func BenchmarkCertReloader_GetCertificate_ReloadEveryCall(b *testing.B) {
	dir := b.TempDir()
	certPath, keyPath, err := genCertKeyFiles(dir)
	if err != nil {
		b.Fatalf("generating cert/key: %v", err)
	}
	r, err := NewCertReloader(certPath, keyPath, WithReloadInterval(time.Nanosecond))
	if err != nil {
		b.Fatalf("creating cert reloader: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := r.GetCertificate(nil); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkCAReloader_GetCertPool_ReloadEveryCall is the CAReloader
// equivalent of BenchmarkCertReloader_GetCertificate_ReloadEveryCall.
func BenchmarkCAReloader_GetCertPool_ReloadEveryCall(b *testing.B) {
	dir := b.TempDir()
	caPath, err := genCAFile(dir, "ca.pem")
	if err != nil {
		b.Fatalf("generating CA: %v", err)
	}
	r, err := NewCAReloader([]string{caPath}, time.Nanosecond)
	if err != nil {
		b.Fatalf("creating CA reloader: %v", err)
	}

	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = r.GetCertPool()
	}
}

// BenchmarkTLSConfigMemoryFootprint reports an absolute bytes-per-instance
// figure for holding many distinct, simultaneously-loaded TLS configs (e.g.
// one per output/listener in a fleet of agents) with reload on versus off.
// This is the axis the reload feature actually scales on - number of
// configured endpoints, not number of connections.
//
// Because each b.N iteration internally does n LoadTLSConfig calls, run this
// benchmark with a small explicit -benchtime (e.g. -benchtime=3x) rather than
// the default auto-scaling or a large -benchtime=Nx shared with other
// benchmarks in the same invocation - otherwise the work multiplies to
// b.N*n LoadTLSConfig calls.
func BenchmarkTLSConfigMemoryFootprint(b *testing.B) {
	const n = 1000

	dir := b.TempDir()
	caPath, err := genCAFile(dir, "ca.pem")
	if err != nil {
		b.Fatalf("generating CA: %v", err)
	}
	certPath, keyPath, err := genCertKeyFiles(dir)
	if err != nil {
		b.Fatalf("generating cert/key: %v", err)
	}
	logger := logp.NewLogger("bench")
	disabled, enabled := false, true

	run := func(b *testing.B, reload CertificateReload) {
		cfg := &Config{
			CAs:               []string{caPath},
			Certificate:       CertificateConfig{Certificate: certPath, Key: keyPath},
			CertificateReload: reload,
		}

		for i := 0; i < b.N; i++ {
			configs := make([]*TLSConfig, 0, n)

			runtime.GC()
			var before runtime.MemStats
			runtime.ReadMemStats(&before)

			for j := 0; j < n; j++ {
				tlsCfg, err := LoadTLSConfig(cfg, logger)
				if err != nil {
					b.Fatal(err)
				}
				configs = append(configs, tlsCfg)
			}

			runtime.GC()
			var after runtime.MemStats
			runtime.ReadMemStats(&after)

			b.ReportMetric(float64(after.HeapAlloc-before.HeapAlloc)/float64(n), "bytes/config")
			runtime.KeepAlive(configs)
		}
	}

	b.Run("ReloadDisabled", func(b *testing.B) {
		run(b, CertificateReload{Enabled: &disabled})
	})
	b.Run("ReloadEnabled", func(b *testing.B) {
		run(b, CertificateReload{Enabled: &enabled, ReloadInterval: time.Hour})
	})
}
