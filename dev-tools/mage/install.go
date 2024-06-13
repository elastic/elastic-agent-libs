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

package mage

import "github.com/elastic/elastic-agent-libs/dev-tools/mage/gotool"

var (
	// GoLicenserImportPath controls the import path used to install go-licenser.
	GoLicenserImportPath = "github.com/elastic/go-license@latest"

	// GoNoticeGeneratorImportPath controls the import path used to install go-licence-detector.
	GoNoticeGeneratorImportPath = "go.elastic.co/go-licence-detector@latest"
)

// InstallGoLicenser target installs go-licenser
func InstallGoLicenser() error {
	return gotool.Install(
		gotool.Install.Package(GoLicenserImportPath),
	)
}

// InstallGoNoticeGen target installs go-licenser
func InstallGoNoticeGen() error {
	return gotool.Install(
		gotool.Install.Package(GoNoticeGeneratorImportPath),
	)
}
