#!/usr/bin/env bash

set -euo pipefail

format_and_replace() {
    echo "$1" | \
    sed \
        -e 's|/app/fake/|/opt/zapret/files/fake/|g' \
        -e 's|/app/targets/|/opt/zapret/ipset/|g' | \
    sed 's/ --/\n--/g'
}

main() {
    if [ -t 0 ] && [ -n "${1:-}" ]; then
        input="$1"
    elif [ ! -t 0 ]; then
        input="$(cat)"
    else
        echo "Использование: $0 \"--параметры...\""
        exit 1
    fi

    echo ""
    format_and_replace "$input"
    echo "# game strat
--new
--filter-udp=88,500,1024-19293,19345-49999,50101-65535
--dpi-desync=fake
--dpi-desync-cutoff=d2
--dpi-desync-any-protocol=1
--dpi-desync-fake-unknown-udp=/opt/zapret/files/fake/quic_initial_www_google_com.bin"
}

main "$@"
