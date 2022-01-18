#!/usr/bin/env bash
set -eou pipefail
reset
[[ -f .envrc ]] && eval "$(cat .envrc)"
INTERFACE_PREFIX=dtun
export REMOTE_DOMAIN=t$IODINE_ID.$REMOTE_DOMAIN_PREFIX.$REMOTE_TLD
conn_ok=
IODINE_ID=2
LOCAL_IFACE="${INTERFACE_PREFIX}${IODINE_ID}"
pidf=$(mktemp)
sbf=$(mktemp)
ping_ec=$(mktemp)

IODINE_CMD="$(eval echo -e "$(command -v iodine) -d $LOCAL_IFACE -4 -f -F $pidf $REMOTE_DOMAIN")"
iob=

MAX_PING_DUR=10

handle_iodine_stdout_line() {
	local l="$(ansi --faint --cyan "$@")"
	local iodine_stdout_pfx="$(nicedate)"
	local p="$(gp)"
	iodine_stdout_pfx="$(ansi --faint --cyan --bg-black --inverse "$iodine_stdout_pfx")"
	iodine_stdout_pfx="${iodine_stdout_pfx} $LOCAL_IFACE"
	if [[ "$p" -gt 0 ]]; then
		iodine_stdout_pfx="${iodine_stdout_pfx} TUNNEL ESTABLISHED <$p>"
	else
		iodine_stdout_pfx="${iodine_stdout_pfx} ESTABLISHING TUNNEL"
	fi
	iodine_stdout_sep="$(ansi --bold --cyan --bg-black "> ")"
	iodine_stdout_pfx="${iodine_stdout_pfx}${iodine_stdout_sep}"
	local msg="${iodine_stdout_pfx}${l}"
	echo >&2 -e "$msg"
}

create_bridge() {
	#	set -x
	BR=brc0
	VIF=eth0
	IF_HOST=h0
	IF_GUEST=g0
	VPFX=203.0.113
	VGW=${VPFX}.1
	VNM=24
	VCIDR=${VPFX}.0/$VNM
	VADDR=${VPFX}.10/$VNM
	IPNS=ns0

	WGNS=wg0
	WGNS_CIDR=10.199.123.0/24
	WGNS_ADDR=10.199.123.10/24
	WGNS_PRIV="245ec72b-9727-4507-8169-70b3987e2506"

	sudo ip link del $BR || true
	sudo ip netns delete $IPNS || true
	sudo brctl addbr $BR
	sudo ip link set $BR up
	sudo ip addr add $VGW/$VNM dev $BR
	sudo ip link add name $IF_HOST type veth peer name $IF_GUEST
	sudo ip link set $IF_HOST up
	sudo brctl addif $BR $IF_HOST
	sudo ip netns add $IPNS
	sudo ip link set $IF_GUEST netns $IPNS
	sudo ip netns exec $IPNS ip link set $IF_GUEST name $VIF
	sudo ip netns exec $IPNS ip addr add $VADDR dev $VIF
	sudo ip netns exec $IPNS ip link set $VIF up
	sudo ip netns exec $IPNS ip route add default via $VGW
	sudo ip netns exec $IPNS ip addr
	sudo ip netns exec $IPNS route -n

	ip netns delete $WGNS 2>/dev/null || true
	ip netns add $WGNS
	ip -n $WGNS link set dev lo up
	ip link add $WGNS type wireguard

	ip link set $WGNS netns $IPNS

	ip netns exec $IPNS wg set $WGNS listen-port 12345
	ip netns exec $IPNS wg set $WGNS fwmark 0
	ip netns exec $IPNS wg set $WGNS private-key <(echo $WGNS_PRIV)
	ip netns exec $IPNS ip address add $WGNS_ADDR dev $WGNS
	ip netns exec $IPNS $WG_BINARY set $WGNS peer 8Mq5RmFbiHwGIuRqmobEihi5T3T1eabzXlb1Mr1f3Ss= preshared-key /dev/null persistent-keepalive 5 endpoint 173.230.142.14:59220 allowed-ips 0.0.0.0/0
	ip netns exec $IPNS ip link set $WGNS up

	ip -n $IPNS -4 address add $WGNS_ADDR dev $WGNS
	ip -n $IPNS link set dev $WGNS mtu 1420 up
	ip -n $IPNS -4 route add 0.0.0.0/0 dev $WGNS

	sudo ip netns exec $IPNS wg showconf $WGNS

	sudo ip netns exec $IPNS ip addr
	sudo ip netns exec $IPNS route -n
	sudo ip netns exec $IPNS $WG_BINARY

	#	set +x
}

detailedate() { date +%FT%T.%3N; }
nicedate() { date +%H:%M:%S; }
ms() { date +%s%3N; }

version_ok() {
	conn_ok=1
	conn_ok_ts=$(ms)
	#ansi --green "\n\nVERSION OK!\n\n"
	#sleep 5
}

handle_line() {
	local l="$@"
	iob="$iob\n$l"
	local MATCH="^Version ok, "
	local HANDLER=version_ok
	if echo -e "$l" | grep -q "$MATCH"; then
		eval $HANDLER "$l"
	fi
}

sb_ping_gw() {
	sb
}

sb() {
	local msg="$(cat $sbf)"
	local color=yellow
	local style="--$color --bold"
	msg="$(ansi $style $msg)"
	echo -e "$msg"
}

_sb_ping_gw() {
	$PING_BINARY -A -4 -D -I $LOCAL_IFACE -n -O -c 20 -w $(($MAX_PING_DUR * 5)) $ip | grep time= | cut -d ' ' -f7 | cut -d= -f2 | sed 's/\.//g' | sparkbar
}

_sb() {
	ps -eo rss --sort rss | tail -20 | sed 's/[[:space:]]//g' | sparkbar
}
rx_pkts=
tx_pkts=
tx_bytes=
rx_bytes=
rx_str=
tx_str=
process_pkts() {
	while read pl; do
		continue
		ansi >&2 --magenta "PL> $pl"
	done < <(pkts | sed 's/^[[:space:]]//g')

}

genmsg() {
	local m="$@"
	local m_pfx="$(ansi --reset-color -n)<$(ansi --underline --white --bg-black "$(gp)")> [$ec]$(ansi --reset-color -n)"
	local m_sfx=
	test "$ok" -eq 1 && process_pkts
	local m="${m_pfx}$m${m_sfx}"
	[[ "$ok" == 1 ]] && m="$(ansi --green --bold "$m")"
	[[ "$ok" != 1 ]] && m="$(ansi --red --bg-black --italic "$m")"

	local check_color=yellow
	test "$ok" -eq 1 && check_color=green
	local check_style="--italic"
	local check_content="✔"

	local conn_color=cyan
	test "$conn_ok" -eq 1 && conn_color=green
	local conn_style="--italic"
	local conn_content="       $(sb)   "
	local _conn="$(ansi --$conn_color $conn_style "$conn_content")"

	local pkgs_content="$rx_str/$tx_str"
	[[ "$ec" != 0 ]] && check_content="✘" && check_color=red && check_content="$check_content (exited $ec)"
	[[ "$ec" == 0 ]] && _conn="$_conn $pkgs_content"
	local check="--$check_color $check_style $check_content"
	local sb_ping_gw=
	#[[ "$ec" == 0 ]]  && sb_ping_gw=" $(sb_ping_gw) "
	msg="$check_content $(ansi --blue --bg-black --bold " ")$(ansi --blue --bg-black --bold --inverse --underline "${LOCAL_IFACE}")$(ansi --blue --bg-black --bold " ") $(date +%H:%M:%S)> took 8s   $(sb)   $sb_ping_gw "
	#${_conn}  $(ansi ${check})   
	#  msg="$(date +%H:%M:%S)> $msg"
	#  msg="${_conn}  $(ansi ${check})    $(date +%H:%M:%S)> $m "

	echo -e "$msg"

}

pinger_pid=
poller_pid=
ip=
ok=
qty=0
started=$(ms)
first_ok=
ok_delay=
failed_qty=0
MAX_FAILED=5
normalize_cur_pps_items() {
	local lim="$((60 / $poll_interval))"
	cur_pps_items="$(echo -e "$cur_pps_items" | tr ' ' '\n' | tail -n $lim | tr '\n' ' ')"
	true
}

ping_log=/tmp/ping.log

pkts() {
	ansi --magenta --bold "$(ifconfig $LOCAL_IFACE | egrep 'RX|TX' | grep packets)"
}

gp() { cat $pidf; }
ok() {
	if [[ "$ok" == 1 && "$first_ok" != "" && "$failed_qty" -lt "$MAX_FAILED" ]]; then
		true
	else
		false
	fi
}
sb=
pkt_qtys=()
get_pkt_qty() { ifconfig $LOCAL_IFACE | grep packets | tr -s ' ' | cut -d' ' -f4 | grep '^[0-9].*' | awk '{s+=$1} END {print s}'; }
cur_pps_items="0 0 0 0 0 0 0 0 0 0 0 0 0 0"
poll_pkt_qty() {
	local cur_qty=
	local last_qty=0
	local cur_pps=
	local last_checked_ms=
	local ms_since_last_check=
	while :; do
		local q=$(get_pkt_qty)
		if [[ "$q" != "" ]]; then
			if [[ "$q" -gt -1 ]]; then
				cur_qty=$(($q - $last_qty))
				if [[ "$last_checked_ms" != "" ]]; then
					ms_since_last_check=$(($(ms) - $last_checked_ms))
					cur_pps=$(($(($(($cur_qty * 1000)) / $(($ms_since_last_check / 1000)))) / 1000))
					cur_pps_items="$cur_pps_items $cur_pps"
					normalize_cur_pps_items
					sb="$(sparkbar $cur_pps_items)"
					echo -e "$sb" >$sbf
					#>&2 ansi --green "$sb"
					#/$(($ms_since_last_check*1000))))
				fi
				last_qty=$q
				last_checked_ms=$(ms)
			fi
		fi
		local msg="ms_since_last_check:$ms_since_last_check|last_qty:$last_qty|last_checked_ms:$last_checked_ms|cur_pps=$cur_pps|cur_qty=$cur_qty"
		#echo >&2 -e "$msg"
		sleep $poll_interval
	done
}

pinger() {
	local ip=$1
	while :; do
		o="$({
			timeout $MAX_PING_DUR $PING_BINARY -4 -D -I $LOCAL_IFACE -n -O -c 1 -w $MAX_PING_DUR $ip 2>&1
			echo $? >$ping_ec
		} | tee -a $ping_log)"
		ec=$(cat $ping_ec)
		qty=$(($qty + 1))
		if [[ "$ec" == 0 ]]; then
			ok=1
			failed_qty=0
			[[ "$first_ok" == "" ]] && first_ok=$(ms) && ok_delay=$(($first_ok - $started))
		else
			ok=0
			failed_qty=$(($failed_qty + 1))
		fi
		[[ "$failed_qty" -gt $MAX_FAILED && "$(gp)" -gt 0 ]] && { kill $(gp) || true; }
		local msg=""
		msg="$(genmsg $msg)"
		echo >&2 -e "$msg"
		sleep 1
		if [[ "$ok" == 1 ]]; then
			sleep 1
		else
			sleep .1
		fi
	done
}

cleanup() {
	echo CLEANUP
	[[ "$pinger_pid" -gt 0 ]] && kill -9 $pinger_pid || true
	[[ "$poller_pid" -gt 0 ]] && kill -9 $poller_pid || true
	unlink "$pidf" || true
}

trap cleanup EXIT

set +e
while read -r l; do
	handle_line "$l"
	[[ "$failed_qty" -gt $MAX_FAILED ]] && exit 1
	handle_iodine_stdout_line "$l"
	ip="$(echo -e "$l" | command grep "^Server tunnel IP is " | cut -d" " -f5)"
	if [[ "$ip" != "" ]]; then
		ansi >&2 --green --bold "Found Remote IP: $ip"
		pinger $ip &
		pinger_pid=$!
		poll_pkt_qty &
		poller_pid=$!
		sleep 2
		create_bridge
	fi
done < <(eval "$IODINE_CMD" 2>&1)
