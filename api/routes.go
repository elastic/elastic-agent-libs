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
	"fmt"
	"net/http"
	_ "net/http/pprof" //nolint:gosec // we want to expose pprof endpoint
	"net/url"

	"github.com/elastic/elastic-agent-libs/config"
	"github.com/elastic/elastic-agent-libs/logp"
	"github.com/elastic/elastic-agent-libs/mapstr"
	"github.com/elastic/elastic-agent-libs/monitoring"
)

// HandlerFunc is an http callback
type HandlerFunc func(http.ResponseWriter, *http.Request)
type lookupFunc func(string) *monitoring.Namespace

var handlerFuncMap = make(map[string]HandlerFunc)

// NewWithDefaultRoutes creates a new server with default API routes.
func NewWithDefaultRoutes(log *logp.Logger, c *config.C, ns lookupFunc) (*Server, error) {
	mux := http.NewServeMux()

	mux.HandleFunc("/", MakeRootAPIHandler(MakeAPIHandler(ns("info"))))
	mux.HandleFunc("/state", MakeAPIHandler(ns("state")))
	mux.HandleFunc("/stats", MakeAPIHandler(ns("stats")))
	mux.HandleFunc("/dataset", MakeAPIHandler(ns("dataset")))

	for api, h := range handlerFuncMap {
		mux.HandleFunc(api, h)
	}
	return New(log, mux, c)
}

// AttachPprof adds /debug/pprof endpoints to the server
func (s *Server) AttachPprof() {
	s.log.Info("Attaching pprof endpoints")
	s.mux.HandleFunc("/debug/pprof/", func(w http.ResponseWriter, r *http.Request) {
		http.DefaultServeMux.ServeHTTP(w, r)
	})

}

// MakeRootAPIHandler creates a HandlerFunc for the root / path
func MakeRootAPIHandler(handler HandlerFunc) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		handler(w, r)
	}
}

// MakeAPIHandler creates an API handler for the given namespace
func MakeAPIHandler(ns *monitoring.Namespace) HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")

		data := monitoring.CollectStructSnapshot(
			ns.GetRegistry(),
			monitoring.Full,
			false,
		)

		prettyPrint(w, data, r.URL)
	}
}

func prettyPrint(w http.ResponseWriter, data mapstr.M, u *url.URL) {
	query := u.Query()
	if _, ok := query["pretty"]; ok {
		fmt.Fprint(w, data.StringToPrint())
	} else {
		fmt.Fprint(w, data.String())
	}
}

// AddHandlerFunc adds a handler to the global handler map.
// Callbacks should be added before calling NewWithDefaultRoutes()
// This is NOT threadsafe
func AddHandlerFunc(api string, h HandlerFunc) error {
	if _, exist := handlerFuncMap[api]; exist {
		return fmt.Errorf("%s already exist", api)
	}
	handlerFuncMap[api] = h
	return nil
}
