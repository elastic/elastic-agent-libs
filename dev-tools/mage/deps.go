package mage

import (
	"fmt"

	"github.com/magefile/mage/mg"

	"github.com/elastic/elastic-agent-libs/dev-tools/mage/gotool"
)

// Deps contains targets related to checking dependencies
type Deps mg.Namespace

// CheckModuleTidy checks if `go mod tidy` was run before the last commit.
func (Deps) CheckModuleTidy() error {
	err := gotool.Mod.Tidy()
	if err != nil {
		return err
	}
	err = assertUnchanged("go.mod")
	if err != nil {
		return fmt.Errorf("`go mod tidy` was not called before the last commit: %w", err)
	}

	return nil
}
