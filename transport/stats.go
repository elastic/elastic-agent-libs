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

package transport

import (
	"context"
	"errors"
	"io"
	"net"
)

type IOStatser interface {
	WriteError(err error)
	WriteBytes(int)

	ReadError(err error)
	ReadBytes(int)
}

type statsConn struct {
	net.Conn
	stats IOStatser
}

func StatsDialer(d Dialer, s IOStatser) Dialer {
	return ConnWrapper(d, func(c net.Conn) net.Conn {
		return &statsConn{c, s}
	})
}

func (s *statsConn) Read(b []byte) (int, error) {
	n, err := s.Conn.Read(b)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		s.stats.ReadError(err)
	}
	s.stats.ReadBytes(n)
	return n, err
}

func (s *statsConn) Write(b []byte) (int, error) {
	n, err := s.Conn.Write(b)
	if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, context.Canceled) {
		s.stats.WriteError(err)
	}
	s.stats.WriteBytes(n)
	return n, err
}
