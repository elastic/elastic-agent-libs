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

package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/transport/httpcommon"
)

const (
	localhostURL = "http://localhost:0"
)

func TestConfiguration(t *testing.T) {
	if !isWindows() {
		t.Skip("Check for User and Security Descriptor")
		return
	}
	t.Run("when user is set", func(t *testing.T) {
		cfg := config.MustNewConfigFrom(map[string]interface{}{
			"host": "unix:///tmp/ok",
			"user": "admin",
		})

		_, err := New(nil, simpleMux(), cfg)
		assert.Equal(t, err == nil, false)
	})

	t.Run("when security descriptor is set", func(t *testing.T) {
		cfg := config.MustNewConfigFrom(map[string]interface{}{
			"host":                "unix:///tmp/ok",
			"security_descriptor": "D:P(A;;GA;;;1234)",
		})

		_, err := New(nil, simpleMux(), cfg)
		assert.Equal(t, err == nil, false)
	})
}

func TestSocket(t *testing.T) {
	if isWindows() {
		t.Skip("Unix Sockets don't work under windows")
		return
	}

	t.Run("socket doesn't exist before", func(t *testing.T) {
		tmpDir := t.TempDir()
		sockFile := tmpDir + "/test.sock"

		cfg := config.MustNewConfigFrom(map[string]interface{}{
			"host": "unix://" + sockFile,
		})

		s, err := New(nil, simpleMux(), cfg)
		require.NoError(t, err)
		go s.Start()
		defer func() {
			err := s.Stop()
			require.NoError(t, err)
			// Make we cleanup behind
			_, err = os.Stat(sockFile)
			require.Error(t, err)
			require.False(t, os.IsExist(err))
		}()

		body := getResponse(t, sockFile, "http://unix/echo-hello")
		assert.Equal(t, "ehlo!", body)

		fi, err := os.Stat(sockFile)
		require.NoError(t, err)
		assert.Equal(t, socketFileMode, fi.Mode().Perm())
	})

	t.Run("starting beat and recover a dangling socket file", func(t *testing.T) {
		sockFile := t.TempDir() + "/test.sock"

		// Create the socket before the server.
		f, err := os.Create(sockFile)
		require.NoError(t, err, "error creating test socket")
		f.Close()

		cfg := config.MustNewConfigFrom(map[string]interface{}{
			"host": "unix://" + sockFile,
		})

		s, err := New(nil, simpleMux(), cfg)
		require.NoError(t, err)
		go s.Start()
		defer func() {
			err := s.Stop()
			require.NoError(t, err, "error stopping test server")
			// Make we cleanup behind
			_, err = os.Stat(sockFile)
			require.Error(t, err)
			require.False(t, os.IsExist(err))
		}()

		body := getResponse(t, sockFile, "http://unix/echo-hello")
		assert.Equal(t, "ehlo!", body)

		fi, err := os.Stat(sockFile)
		require.NoError(t, err, "error opening test socket")
		assert.Equal(t, socketFileMode, fi.Mode().Perm(), "incorrect mode for file %s", sockFile)
	})
}

func isWindows() bool {
	return runtime.GOOS == "windows"
}

func getResponse(t *testing.T, sockFile, url string) string {
	client := func(sockFile string) http.Client {
		return http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", sockFile)
				},
			},
		}
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	require.NoError(t, err)

	c := client(sockFile)
	r, err := c.Do(req)
	require.NoError(t, err)
	defer r.Body.Close()

	body, err := httpcommon.ReadAll(r)
	require.NoError(t, err)
	return string(body)
}

func TestHTTP(t *testing.T) {
	cfg := config.MustNewConfigFrom(map[string]interface{}{
		"host": localhostURL,
	})

	s, err := New(nil, simpleMux(), cfg)
	require.NoError(t, err)
	go s.Start()
	defer func() {
		err := s.Stop()
		require.NoError(t, err, "error stopping test server")
	}()

	req, err := http.NewRequestWithContext(context.Background(), "GET", "http://"+s.l.Addr().String()+"/echo-hello", nil)
	require.NoError(t, err)
	r, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() {
		err := r.Body.Close()
		require.NoError(t, err)
	}()

	body, err := httpcommon.ReadAll(r)
	require.NoError(t, err)

	assert.Equal(t, "ehlo!", string(body))
}

func simpleMux() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/echo-hello", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "ehlo!")
	})
	return mux
}

func TestAttachHandler(t *testing.T) {
	cfg := config.MustNewConfigFrom(map[string]interface{}{
		"host": localhostURL,
	})

	s, err := New(nil, simpleMux(), cfg)
	require.NoError(t, err)
	go s.Start()
	defer func() {
		err := s.Stop()
		require.NoError(t, err, "error stopping test server")
	}()

	h := &testHandler{}

	err = s.AttachHandler("/test", h)
	require.NoError(t, err)

	req, err := http.NewRequestWithContext(context.Background(), "GET", "http://"+s.l.Addr().String()+"/test", nil)
	require.NoError(t, err)
	r, err := http.DefaultClient.Do(req)
	require.NoError(t, err)
	defer func() {
		err := r.Body.Close()
		require.NoError(t, err)
	}()

	body, err := httpcommon.ReadAll(r)
	require.NoError(t, err)

	assert.Equal(t, "test!", string(body))

	err = s.AttachHandler("/test", h)
	assert.NotNil(t, err)
}

type testHandler struct{}

func (t *testHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "test!")
}
