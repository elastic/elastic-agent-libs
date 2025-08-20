// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package file

import (
	"fmt"
	"os"
	"time"
)

type RotateOpts struct {
	RenameRetryDuration time.Duration
	RenameRetryInterval time.Duration
}

type RotateOpt func(*RotateOpts)

func WithRenameRetries(duration, interval time.Duration) RotateOpt {
	return func(opts *RotateOpts) {
		opts.RenameRetryDuration = duration
		opts.RenameRetryInterval = interval
	}
}

func rename(src, dst string, options RotateOpts) error {
	if options.RenameRetryDuration == 0 && options.RenameRetryInterval == 0 {
		return os.Rename(src, dst)
	}

	return retryingRename(src, dst, options.RenameRetryDuration, options.RenameRetryInterval)
}

// retryingRename attempts to rename a file from src to dst, retrying
// every retryInterval until the retryDuration duration has elapsed.
func retryingRename(src, dst string, retryDuration, retryInterval time.Duration) error {
	var err error
	for start := time.Now(); time.Since(start) < retryDuration; time.Sleep(retryInterval) {
		err = os.Rename(src, dst)
		if err == nil {
			// Rename succeeded; no more retries needed
			return nil
		}
	}

	if err != nil {
		return fmt.Errorf("failed to rename %s to %s after %v: %w", src, dst, retryDuration, err)
	}

	return nil
}
