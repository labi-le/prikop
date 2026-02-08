#!/usr/bin/env bash

URL="https://api.fastly.com/public-ip-list"

curl -s "$URL" | jq -r '
  .addresses[]?
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
