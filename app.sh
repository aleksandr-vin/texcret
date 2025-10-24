#!/usr/bin/env bash

set -e

# mkcert -install
# mkcert $(hostname) localhost 127.0.0.1 ::1

key_pem=$(echo $(hostname)*-key.pem)


(sleep 2 && open https://$(hostname) ) &


uvicorn app:app --host 0.0.0.0 --port 443 --ssl-keyfile ${key_pem} --ssl-certfile ${key_pem%-key.pem}.pem
