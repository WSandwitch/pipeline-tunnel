#!/bin/sh
set -e

SCRIPT_DIR="$(dirname "$0")"
cmd="ruby /app/tests/tester.rb -S /app/build -M /app/build/tests/test_modules"

case "${1:-}" in
  "")
    exec "$SCRIPT_DIR/runindocker.sh" $cmd --list-configs
    ;;
  all)
    exec "$SCRIPT_DIR/runindocker.sh" $cmd test_integration.rb
    ;;
  *)
    exec "$SCRIPT_DIR/runindocker.sh" $cmd "$@"
    ;;
esac
