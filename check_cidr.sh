#!/usr/bin/env bash

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <CIDR_FILE> <URL>"
    exit 1
fi

FILE="$1"
URL="$2"

if [ ! -f "$FILE" ]; then
    echo "Error: File '$FILE' not found."
    exit 1
fi

RAW_OUTPUT=$(curl -s -vL -o /dev/null "$URL" 2>&1)

TARGET_IP=$(echo "$RAW_OUTPUT" | grep "Trying" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -n 1)

if [ -z "$TARGET_IP" ]; then
    echo "Error: Could not extract IP."
    exit 1
fi

SIZE_BYTES=$(echo "$RAW_OUTPUT" | grep -i "< content-length:" | tail -n 1 | awk '{print $3}' | tr -d '\r')

echo "Target IP: $TARGET_IP"

if [[ -n "$SIZE_BYTES" && "$SIZE_BYTES" =~ ^[0-9]+$ ]]; then
    SIZE_KB=$(awk "BEGIN {printf \"%.2f\", $SIZE_BYTES/1024}")
    echo "Size: ${SIZE_KB} KB (Header)"
else
    echo "Size: Unknown (No Content-Length header or Chunked encoding)"
fi

awk -v target_ip="$TARGET_IP" '
function ip2int(ip) {
    split(ip, octets, ".")
    return (octets[1] * 16777216) + (octets[2] * 65536) + (octets[3] * 256) + octets[4]
}

BEGIN {
    t_int = ip2int(target_ip)
    found = 0
}

{
    if ($0 == "" || $0 ~ /^#/) next

    split($1, cidr, "/")
    net_ip = cidr[1]
    mask = cidr[2]
    if (mask == "") mask = 32

    start_int = ip2int(net_ip)
    size = 2 ^ (32 - mask)
    end_int = start_int + size - 1

    if (t_int >= start_int && t_int <= end_int) {
        print "MATCH: " $1
        found = 1
        exit 0
    }
}

END {
    if (found == 0) {
        print "NO MATCH"
        exit 1
    }
}
' "$FILE"
