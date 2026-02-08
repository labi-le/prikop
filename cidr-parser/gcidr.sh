#!/usr/bin/env bash

URL="https://www.gstatic.com/ipranges/cloud.json"

curl -s "$URL" | jq -r '
  .prefixes[] | 
  select(.ipv4Prefix != null) | 
  .ipv4Prefix
' | sort | awk '
BEGIN { 
  print "\"target\": ["
}
{
  if (NR > 1) printf ",\n"
  printf "  \"%s\"", $0
}
END { 
  print "\n]" 
}
'
