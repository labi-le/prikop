#!/bin/sh
# discord-voice-dpi-test — is Discord voice UDP getting through the DPI?
#
# Capture-based test that needs NO knowledge of local/remote IPs and runs
# ANYWHERE tcpdump exists: your own machine (preferred) or, piped over ssh, a
# router of any platform. Direction is inferred purely from which side uses a
# Discord voice port, so it behaves identically on a LAN host or a router WAN.
#
# Why sniffing your own machine is a valid DPI test: the bypass signal is
# BIDIRECTIONALITY. discord.media only answers if our (desynced) packets crossed
# the DPI; if the DPI blocks voice, no inbound packets reach us either. So
# "inbound present" == "voice UDP survives the DPI", wherever you capture.
#
# Usage — join a Discord voice call first (and talk to generate media):
#   local :  sudo sh voice-dpi-test.sh [seconds] [iface]
#   router:  ssh <host> 'sh -s [seconds] [iface]' < voice-dpi-test.sh
#            (iface e.g. wan; omit to auto-detect the default-route interface)
#
# Discord voice: RTP on udp 19294-19344 / 50000-50100; IP-discovery carries the
# STUN magic cookie 0x2112a442. NOTE: BitTorrent also squats 50000-50100 — the
# Discord flow is the bidirectional one that SURGES (~50 pkt/s) when you talk;
# ports 19294-19344 are Discord-only.

DUR="${1:-20}"
IFACE="${2:-}"

[ "$(id -u)" -ne 0 ] && echo "note: raw capture needs root — use sudo (or root over ssh)" >&2

if [ -z "$IFACE" ]; then
	IFACE=$(ip -o route get 1.1.1.1 2>/dev/null | sed -n 's/.* dev \([^ ]*\).*/\1/p')
	[ -z "$IFACE" ] && IFACE=$(ip route 2>/dev/null | awk '/^default/{print $5; exit}')
	[ -z "$IFACE" ] && IFACE=$(route -n get default 2>/dev/null | awk '/interface:/{print $2}')
	[ -z "$IFACE" ] && IFACE=any
fi

FILTER='udp and (portrange 19294-19344 or portrange 50000-50100 or udp[12:4]=0x2112a442)'
TMP="${TMPDIR:-/tmp}/dvdt.$$"
echo "iface=$IFACE  duration=${DUR}s  — talk during the capture to see media"

if command -v timeout >/dev/null 2>&1; then
	timeout "$DUR" tcpdump -ni "$IFACE" -tt -c 200000 "$FILTER" >"$TMP" 2>/dev/null
else
	tcpdump -ni "$IFACE" -tt -c 200000 "$FILTER" >"$TMP" 2>/dev/null &
	tp=$!; sleep "$DUR"; kill "$tp" 2>/dev/null; wait "$tp" 2>/dev/null
fi

n=$(wc -l <"$TMP" 2>/dev/null || echo 0)
echo "captured $n voice-candidate packets"
if [ "$n" -eq 0 ]; then
	echo "-> nothing. In a call? Try a longer window, pass the iface, or check perms."
	rm -f "$TMP"; exit 0
fi

res=$(awk '
	function voice(p){ return (p>=19294&&p<=19344)||(p>=50000&&p<=50100) }
	$2=="IP" && /UDP/ {
		src=$3; dst=$5; sub(/:$/,"",dst); len=$NF+0
		sp=src; sub(/.*\./,"",sp); sp+=0
		dp=dst; sub(/.*\./,"",dp); dp+=0
		sip=src; sub(/\.[0-9]+$/,"",sip)
		dip=dst; sub(/\.[0-9]+$/,"",dip)
		if      (voice(sp)) { k=sip"."sp; ipk[k]++; ib[k]+=len; seen[k]=1 }
		else if (voice(dp)) { k=dip"."dp; opk[k]++; ob[k]+=len; seen[k]=1 }
	}
	END{
		for (k in seen){ o=opk[k]+0; i=ipk[k]+0
			printf "%d\t%s\tout=%d(%dB)\tin=%d(%dB)\t%s\n", o+i, k, o, ob[k]+0, i, ib[k]+0,
				(i>0 ? "BIDIRECTIONAL -> voice UDP crosses DPI" : "OUTBOUND-ONLY -> blocked") }
	}' "$TMP" | sort -rn)

echo "--- voice flows (server ip.port) ---"
echo "$res" | head -8 | cut -f2-
verdict=$(echo "$res" | head -1 | cut -f5-)
echo "==> top flow: ${verdict:-none}"
rm -f "$TMP"
