# elastic-agent-libs

This repository is the home to the common libraries used by Elastic Agent and Beats.

Provided packages:
* `github.com/elastic/elastic-agent-libs/atomic` Atomic operations for integer and boolean types.
* `github.com/elastic/elastic-agent-libs/config` the previous `config.go` file from `github.com/elastic/beats/v7/libbeat/common`. A minimal wrapper around `github.com/elastic/go-ucfg`. It contains helpers for merging and accessing configuration objects and flags.
* `github.com/elastic/elastic-agent-libs/str` the previous `stringset.go` file from `github.com/elastic/beats/v7/libbeat/common`. It provides a string set implementation. 
* `github.com/elastic/elastic-agent-libs/file` is responsible for rotating and writing input and output files.
* `github.com/elastic/elastic-agent-libs/logp` is the well known logger from libbeat.
