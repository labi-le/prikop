#!/usr/bin/env bash

FILE="$1"

if [ -z "$FILE" ] || [ ! -f "$FILE" ]; then
    echo "Usage: $0 <CIDR_FILE> <URL>"
    exit 1
fi

check_ip() {
    ip=$1

    domain=$(host -W 1 -t PTR "$ip" 2>/dev/null | awk '/pointer/ {print $NF}' | sed 's/\.$//')

    if [ -z "$domain" ]; then domain="-"; fi

    res=$(curl -s -L -k -m 2 "http://$ip")
    if [ -n "$res" ]; then
        title=$(echo "$res" | grep -oEi '<title>(.*)</title>' | sed -e 's/<[^>]*>//g' | head -n 1)
        echo -e "\033[0;32m$ip | http | $domain | ${title:-[No Title]}\033[0m"
    fi

    res_ssl=$(curl -s -L -k -m 2 "https://$ip")
    if [ -n "$res_ssl" ]; then
        title=$(echo "$res_ssl" | grep -oEi '<title>(.*)</title>' | sed -e 's/<[^>]*>//g' | head -n 1)
        echo -e "\033[0;32m$ip | https | $domain | ${title:-[No Title]}\033[0m"
    fi
}
export -f check_ip

nmap -n -sL -iL "$FILE" | awk '/Nmap scan report/{print $NF}' | xargs -P 50 -I {} bash -c 'check_ip "$@"' _ {}
