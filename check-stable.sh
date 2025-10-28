#!/usr/bin/env bash
#
# Check that stable version can be installed
#

set -e

uv run --with git+https://github.com/aleksandr-vin/texcret.git@stable \
       --no-project \
       -- \
       texcret --help
