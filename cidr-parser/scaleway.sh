#!/usr/bin/env bash

URL="https://raw.githubusercontent.com/scaleway/docs-content/refs/heads/main/pages/account/reference-content/scaleway-network-information.mdx"

curl -s "$URL" | grep -oP '\* `\K[\d./]+(?=`)' | sort -u | awk '
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
