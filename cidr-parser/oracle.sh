#!/usr/bin/env bash

URL="https://docs.oracle.com/en-us/iaas/tools/public_ip_ranges.json"

curl -s "$URL" | jq -r '
  .regions[].cidrs[]? | 
  select(.cidr != null) | 
  .cidr
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
