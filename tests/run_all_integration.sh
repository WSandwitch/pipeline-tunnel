#!/bin/sh
set -e
exec "$(dirname "$0")/runindocker.sh" ruby /app/tests/tester.rb test_integration.rb
