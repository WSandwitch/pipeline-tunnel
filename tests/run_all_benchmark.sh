#!/bin/sh
set -e
BUILD_DIR=/tmp/modtunnel-hostbuild
MOD_DIR="$BUILD_DIR/tests/test_modules"
exec "$(dirname "$0")/tester.rb" -S "$BUILD_DIR" -M "$MOD_DIR" test_benchmark.rb
