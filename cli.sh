#!/usr/bin/env bash

set -e


# mkcert -install
# mkcert $(hostname) localhost 127.0.0.1 ::1

key_pem=${KEY_PEM-$(echo $(hostname)*-key.pem)}

python texcrets_cli.py load-secrets \
  --origin https://mac.home --cert ${key_pem%-key.pem}.pem --key ${key_pem}