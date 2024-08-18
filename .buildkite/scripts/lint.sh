#!/bin/bash
set -euo pipefail

echo "--- Mage notice"
mage notice

echo "--- Mage check"
mage -v check
