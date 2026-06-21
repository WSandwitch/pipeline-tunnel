#!/bin/sh
set -e

MODULE_PATH="${MODULE_PATH:-/app/modules}"

build_args() {
    args=""
    [ -n "$MODULE_PATH" ] && args="$args -M $MODULE_PATH"
    case "$THREADS" in
        0) args="$args -t" ;;
        [1-9]*) args="$args -t$THREADS" ;;
    esac
    [ -n "$HEARTBEAT" ] && args="$args -H $HEARTBEAT"
    case "$VERBOSITY" in
        1) args="$args -v" ;;
        2) args="$args -vv" ;;
        3) args="$args -vvv" ;;
    esac
    echo "$args"
}

case "${MODE:-server}" in
    server)
        args=$(build_args)
        [ -z "$LISTEN" ]   && LISTEN="0.0.0.0:34443"
        [ -z "$PASSWORD" ] && { echo "FATAL: PASSWORD is required"; exit 1; }
        exec /app/ppltunnel-server -l "$LISTEN" -A "$PASSWORD" $args
        ;;
    client)
        args=$(build_args)
        [ -z "$LISTEN" ] && { echo "FATAL: LISTEN is required (format: [bind:]port:target_host:target_port)"; exit 1; }
        [ -z "$CHAIN" ]  && { echo "FATAL: CHAIN is required (format: host:port,password[;module|params]...)"; exit 1; }
        exec /app/ppltunnel-client -L "$LISTEN" $args $CHAIN
        ;;
    *)
        echo "FATAL: MODE must be 'server' or 'client'"
        exit 1
        ;;
esac
