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
}

main "$@"
