#!/usr/bin/env bash

URL="https://ip-ranges.amazonaws.com/ip-ranges.json"

curl -s "$URL" | jq -r '
  .prefixes[]? |
  select(.ip_prefix != null) |
  .ip_prefix
' | sort -u | awk '
BEGIN {
  print "\"cidrs\": ["
}
{
  if (NR > 1) printf ",\n"
  printf "  \"%s\"", $0
}
END {
  print "\n]"
}
'
