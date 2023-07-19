#!/usr/bin/env bash

set -o nounset
set -o errexit

source /root/venv/bin/activate

exec /usr/local/sbin/getmail-daemon
