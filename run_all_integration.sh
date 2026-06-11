#!/bin/sh
set -e
cd "$(dirname "$0")"
exec ./tests/runindocker.sh test_integration.rb
