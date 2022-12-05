// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package loader

import (
	"fmt"
	"path/filepath"
)

// DiscoverFiles takes a slices of wildcards patterns and try to discover all the matching files
// recursively and will stop on any errors.
func DiscoverFiles(patterns ...string) ([]string, error) {
	files := make([]string, 0)
	for _, pattern := range patterns {
		f, err := filepath.Glob(pattern)
		if err != nil {
			return files, fmt.Errorf("error while loading glob pattern: %w", err)
		}

		if len(f) > 0 {
			files = append(files, f...)
		}
	}

	return files, nil
}
