#!/bin/sh
set -e

cmd="$(dirname "$0")/tester.rb -S /tmp/modtunnel-hostbuild -M /tmp/modtunnel-hostbuild/tests/test_modules"

case "${1:-}" in
  "")
    exec $cmd --list-configs
    ;;
  all)
    exec $cmd test_benchmark.rb
    ;;
  *)
    exec $cmd "$@" test_benchmark.rb
    ;;
esac
