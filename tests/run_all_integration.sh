#!/bin/sh
set -e
exec "$(dirname "$0")/runindocker.sh" ruby /app/tests/tester.rb -S /app/build -M /app/build/tests/test_modules test_integration.rb
