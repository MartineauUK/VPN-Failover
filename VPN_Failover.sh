#!/bin/sh
# shellcheck disable=SC2086,SC2068,SC2039,SC2242,SC2027,SC2155,SC2046
VER="v1.15"
#======================================================================================================= © 2016-2019 Martineau, v1.15
#
# Check every 30 secs, and switch to alternate VPN Client if current VPN Client is DOWN, or expected cURL data transfer is 'SLOW'
#
#          VPN_Failover   [-h|--help] | {vpn_instance to monitor} [ignore='csv_vpn_clients] [interval='seconds'] [timeout='seconds']] [force[big | small]
#                         [curlrate='number'] [minrates='csv_rates'] [verbose=y] [delay='seconds'] [noswitch[='hhmm-hhmm'[,...]]] [silent] [multiconfig] [once]
#
#          VPN_Failover   1
#                         Monitor VPN Client 1 every 30 secs and if DOWN switch to VPN Client 2 and then monitor VPN Client 2
#                         (This initiates the round robin for ALL VPN Clients (if configured) in sequence 2,3,4,5 then back to VPN Client 1)
#          VPN_Failover   1 once
#                         As above, but the script terminates immediately and exits if the VPN Client 1 connection is UP.
#          VPN_Failover   2 ignore=3,4,5
#                         Monitor VPN Client 2 every 30 secs and if DOWN switch to VPN Client 1 and then monitor VPN Client 1
#                         (This initiates the round robin ONLY for the two VPN Clients; VPN1 (Primary) and VPN2 (Fail-over)
#          VPN_Failover   2 interval=60
#                         Monitor VPN Client 2 every 60 secs and if DOWN switch to VPN Client 3 and then monitor VPN Client 3
#          VPN_Failover   5 timeout=45
#                         Monitor VPN Client 5 every 30 secs and if DOWN switch to VPN Client 1 and allow max 45 secs for Client 1 to start
#                         then monitor VPN Client 1
#          VPN_Failover   3 force curlrate=1M
#                         If the 12MB cURL transfer rate is <1048576 Bytes per second, then treat this as VPN Client 3 'DOWN'
#                         (This cURL rate is not applicable to other VPN Clients if a switch occurs)
#          VPN_Failover   3 force curlrate=1M verbose=y
#                         As previous example, but additional cURL transfer statistics/progress messages are shown on the console. (Useful to determine appropriate 'minrates=')
#          VPN_Failover   3 forcesmall curlrate=1000 verbose=y noswitch=08:59-17:00
#                         If the 433Byte cURL transfer rate is <1000 Bytes per second, no (disruptive) VPN Switch is performed during 'office' hours 9-5
#          VPN_Failover   3 forcesmall curlrate=1000 verbose=y noswitch
#                         If the 433Byte cURL transfer rate is <1000 Bytes per second, no (disruptive) VPN Switch is performed at ANY time.
#                         (If VPN Client 3 is DOWN; the 'noswitch' directive is temporarily ignored to ensure the next round-robin VPN Client is started and found to be UP)
#          VPN_Failover   1 force curlrate=900K minrates=?,500k,123456
#                         Explicitly override three of the VPN Client minimum cURL rates e.g. VPN1=9921600B/sec,VPN2=512000B/sec and VPN3=123456B/sec (VPN4 and VPN5 remain 0B/sec)
#                         If the 12MB cURL transfer rate is <9921600 Bytes per second, then treat this as VPN Client 1 'DOWN'
#                         (If a switch to VPN Client 2 occurs, a min rate of 512000B/sec will be expected, and if a switch to VPN3 occurs, a min rate of 123456B/sec will be expected)
#          VPN_Failover   1 multiconfig
#                         Monitor VPN Client 1 every 30 secs and if DOWN, retrieve the next round-robin VPN Client 1 config from '/jffs/configs/VPN_Failover' and restart VPN Client 1.
#                         (So rather than be limited by 5 VPN GUI configs, you can now specify an unlimited custom server list for a SINGLE VPN ISP
#                         e.g. 1 vpn.LA.server     553     udp     #HMA Los Angeles
#                              1 vpn.NY.server     443     tcp     #HMA New York
#                              1 vpn.SF.server     1194    udp     #HMA San Francisco

# https://pastebin.com/RNPJDhjJ

# Script may be initiated by openvpn-event vpnclientX-up/vpnclientX-route-pre-up ONLY if one VPN Client is ACTIVE at any given time!!!!
#
#       VPN_ID=${dev:4:1}
#       /jffs/scripts/VPN_Failover.sh "$VPN_ID" "delay=60" &
#
# and subsequently needs to be terminated by openvpn-event vpnclientX-route-pre-down (unless the termination is requested by this script)
#       MYROUTER=$(nvram get computer_name)
#       if [ -d "/tmp/mnt/"$MYROUTER ]; then
#          MOUNT="/tmp/mnt/"$MYROUTER
#       else
#          MOUNT="/tmp"
#       fi
#       LOCKFILE=$MOUNT"/vpnclient"$VPN_ID"-monitor"
#       if [ -z "$(grep "NOKILL" $LOCKFILE)" ];then
#          PID=$(cat $LOCKFILE)
#          [ "$PID" != "NOKILL" ] && kill $PID
#          rm $LOCKFILE
#          logger -st "($(basename $0))" $$ "VPN Failover Monitor self-destruct requested....." $LOCKFILE "RC="$?
#       fi

#
# A Primary (VPN1) / Failover (VPN2) between ONLY VPN1 and VPN2 can be requested as follows (assuming VPN Clients 3,4 and 5 are NOT configured)
#           e.g.
#           Use 'sh /jffs/scripts/VPN_Failover.sh 2 &'
#   but if VPN Clients 3,4 and 5 are configured, you need to EXPLICITLY exclude VPN Clients 3,4 and 5 from being included in the round-robin
#           e.g.
#           Use 'sh /jffs/scripts/VPN_Failover.sh 2 ignore=3,4,5 &'
#

# Print between line beginning with'#==' to first blank line inclusive
ShowHelp() {
  awk '/^#==/{f=1} f{print; if (!NF) exit}' $0
}
Say() {
  # shellcheck disable=SC2068
  echo -e $$ $@ | logger -st "($(basename $0))"
}
SayT() {
  # shellcheck disable=SC2068
  echo -e $$ $@ | logger -t "($(basename $0))"
}
# shellcheck disable=SC2034
ANSIColours() {

  cRESET="\e[0m"
  cBLA="\e[30m"
  cRED="\e[31m"
  cGRE="\e[32m"
  cYEL="\e[33m"
  cBLU="\e[34m"
  cMAG="\e[35m"
  cCYA="\e[36m"
  cGRA="\e[37m"
  cBGRA="\e[90m"
  cBRED="\e[91m"
  cBGRE="\e[92m"
  cBYEL="\e[93m"
  cBBLU="\e[94m"
  cBMAG="\e[95m"
  cBCYA="\e[96m"
  cBWHT="\e[97m"
  aBOLD="\e[1m"
  aDIM="\e[2m"
  aUNDER="\e[4m"
  aBLINK="\e[5m"
  aREVERSE="\e[7m"
  cRED_="\e[41m"
  cGRE_="\e[42m"
}
# Function Parse(String delimiter(s) variable_names)
Parse() {
  #
  #     Parse       "Word1,Word2|Word3" ",|" VAR1 VAR2 REST
  #             (Effectivley executes VAR1="Word1";VAR2="Word2";REST="Word3")
  # shellcheck disable=SC2039
  local string IFS

  TEXT="$1"
  IFS="$2"
  shift 2
  read -r -- "$@" <<EOF
$TEXT
EOF
}
Check_VPN() {

  CNT=0
  STATUS="FAIL"

  local ARG1=$1
  local ARG2=$2
  local ARG3=$3

  if [ -n "$(echo "$IGNORE_VPN" | grep -oF "$3")" ]; then
    echo "IGNORE" # VPN Client is excluded from round robin...so spoof 'OK' status
    return
  fi

  local VPNADDR=$(Get_VPN_ADDR $3)
  if [ -z "$VPNADDR" ]; then
    echo "NOTCONFIG" # VPN Client isn't configured...so spoof 'OK' status
    return
  fi

  local PING_INTERFACE=
  local CURL_INTERFACE=
  if [ -n "$DEV" ]; then # Specific interface requested?
    PING_INTERFACE="-I "$DEV
    CURL_INTERFACE="--interface "$DEV
  fi

  # If the WAN IP is '0.0.0.0' then no point in pinging this as it will actually ping 127.0.0.1 and give a false positive.
  if [ "$1" == "0.0.0.0" ]; then
    return 1
  fi

  echo -en $cBYEL >&2
  if [ "$1" != "CURL" ]; then # Assume $1 is a PING target
    while [ $CNT -lt $TRIES ]; do
      ping $PING_INTERFACE -q -c 1 -W 2 $1 2>/dev/null
      local RC=$?
      if [ $RC -eq 0 ]; then
        STATUS=1
        break
      else
        sleep 1
        CNT=$((CNT + 1))
      fi
    done
  else
    IP=$(curl $CURL_INTERFACE --connect-timeout 5 -s "http://ipecho.net/plain") # Max 15 char retrieval
    RC15=$?

    if [ -n "$IP" ]; then
      STATUS="OK"
    else
      # Hmmmm, if the 15 byte IP retrieval didn't work, we should return *immediately* with FAIL
      # CURLE_COULDNT_CONNECT (7)       tun1X isn't UP?
      # CURLE_INTERFACE_FAILED (45) tun1X interface can't be used i.e. bind to tun1X fails because VPN isn't UP?
      if [ "$RC15" != "0" ]; then # v1.09
        echo "FAIL"
        return
      fi
    fi
  fi

  # FORCE a cURL data transfer retrieval to confirm?
  if [ "$2" != "NOCURL" ]; then
    #if [ "$VERBOSE" == "verbose" ];then                    # v1.08
    TXT_RATE=
    if [ $FORCE_WGET_MIN_RATE -gt 0 ]; then
      TXT_RATE=" NOTE: Transfer rate must be faster than "$FORCE_WGET_MIN_RATE" Bytes/sec"
    fi
    echo -en $cBWHT >&2
    CURL_TXT="Starting VPN Client $3 cURL 'big' data transfer.....(Expect 12MB approx @3.1MB/sec on 20Mbps download = 00:04 secs)"
    if [ "$2" == "$FORCE_WGET_500B" ]; then
      CURL_TXT="Starting VPN Client $3 cURL 'small' data transfer.....(Expect 500Byte download = <1 second)"
    fi
    if [ -n "$CURL_TXT" ]; then
      SayT $CURL_TXT
      echo -e "\t\t"$(date +"%H:%M:%S") $CURL_TXT >&2
    fi

    #if [ -n "$TXT_RATE" ];then
    #SayT $TXT_RATE
    #echo -e "\t\t\t"$TXT_RATE"\n" >&2
    #fi
    echo -en $cBYEL >&2
    #fi
    WGET_DATA=$2
    #wget -O /dev/null -t2 -T2 $WGET_DATA
    if [ "$VERBOSE" == "verbose" ]; then # v1.08
      RESULTS=$(curl $CURL_INTERFACE $WGET_DATA -w "%{time_connect},%{time_total},%{speed_download},%{http_code},%{size_download},%{url_effective}\n" -o /dev/null)
      echo -e >&2
    else
      RESULTS=$(curl $CURL_INTERFACE -s $WGET_DATA -w "%{time_connect},%{time_total},%{speed_download},%{http_code},%{size_download},%{url_effective}\n" -o /dev/null)
    fi
    RC=$?
    if [ $RC -eq 0 ]; then
      STATUS="OK"
      FORCE_OK=1 # Used to make this a priority status summary
      case "$2" in
        "$FORCE_WGET_12MB")
          SayT "cURL $(($(echo $RESULTS | cut -d',' -f5) / 1000000))MByte transfer took:" $(printf "00:%05.2f secs @%6.0f B/sec" "$(echo $RESULTS | cut -d',' -f2)" "$(echo $RESULTS | cut -d',' -f3)")
          echo -e $cBWHT"\t\t"$(date +"%H:%M:%S") "VPN Client" $3 "cURL $(($(echo $RESULTS | cut -d',' -f5) / 1000000))MByte transfer took:" $(printf "00:%05.2f secs @%6.0f B/sec" "$(echo $RESULTS | cut -d',' -f2)" "$(echo $RESULTS | cut -d',' -f3)") >&2
          ;;
        "$FORCE_WGET_500B")
          SayT "cURL $(($(echo $RESULTS | cut -d',' -f5)))Byte transfer took:" $(printf "00:%05.2f secs @%6.0f B/sec" "$(echo $RESULTS | cut -d',' -f2)" "$(echo $RESULTS | cut -d',' -f3)")
          echo -e $cBWHT"\t\t"$(date +"%H:%M:%S") "VPN Client" $3 "cURL $(($(echo $RESULTS | cut -d',' -f5)))Byte transfer took:" $(printf "00:%05.2f secs @%6.0f B/sec" "$(echo $RESULTS | cut -d',' -f2)" "$(echo $RESULTS | cut -d',' -f3)") >&2
          ;;
        *)
          SayT "cURL $(($(echo $RESULTS | cut -d',' -f5)))transfer took:" $(printf "00:%05.2f secs" "$(echo $RESULTS | cut -d',' -f2)")
          echo -e $cBWHT"\t\t"$(date +"%H:%M:%S") "VPN Client" $3 "cURL $(($(echo $RESULTS | cut -d',' -f5)))transfer took:" $(printf "00:%05.2f secs" "$(echo $RESULTS | cut -d',' -f2)") >&2
          ;;
      esac

      # Check if transfer rate is less than the specified acceptable rate
      #Say "***DEBUG FORCE_WGET_MIN_RATE="$FORCE_WGET_MIN_RATE
      if [ $(echo $RESULTS | cut -d',' -f3 | cut -d'.' -f1) -lt $FORCE_WGET_MIN_RATE ]; then
        STATUS="FAIL"
        echo -en ${cBRED}$ALARMBELL"\n" >&2
        SayT "***ERROR VPN Client $3 cURL file transfer rate '"$(echo $RESULTS | cut -d',' -f3 | cut -d'.' -f1)"' Bytes/sec, is less than the acceptable minimum specified '"$FORCE_WGET_MIN_RATE"' Bytes/sec"
        echo -e "\t\tVPN Client $3 cURL file transfer rate '"$(echo $RESULTS | cut -d',' -f3 | cut -d'.' -f1)"' Bytes/sec, is less than the acceptable minimum specified '"$FORCE_WGET_MIN_RATE"' Bytes/sec" >&2
        echo -en $cBYEL >&2
        METHOD=" using MINIMIUM acceptable cURL transfer rate"
      fi
    else
      echo -en $cBRED >&2
      if [ "$VERBOSE" == "verbose" ]; then # v1.08
        Say "***ERROR WGET '"$WGET_DATA"' transfer FAILED RC="$RC
      fi

      FORCE_OK=0
      if [ $RC -ne 8 ]; then
        STATUS="FAIL" # Override PING/curl status!!
      else
        Say "*Warning WGET '"$WGET_DATA"' URL invalid?" # URL invalid so could be OFFLINE so ignore it
      fi
    fi
  fi

  echo $STATUS # OK, FAIL-means switch VPN Client
}
Check_VPNState() {

  local i=0
  local OK=0

  local VPNTAG="$(nvram get vpn_client$1_desc)" # Added to GUI in v380.68
  if [ -z "$VPNTAG" ]; then
    local VPNTAG=$(grep -i "11"$1 /etc/iproute2/rt_tables | awk '{print $2}')
  fi

  if [ "$2" = "2" ]; then
    local WSTATE="connect"
  fi
  if [ "$2" = "0" ]; then
    local WSTATE="disconnect"
  fi
  #while sleep 1; do logger "vpn_client$1_state is `nvram get vpn_client$1_state`"; done    # Command line equivalent
  echo -e $cBMAG"\t\tWaiting" $TIMEOUT "secs for VPN Client" $1 "("$VPNTAG") to" $WSTATE"....." >&2
  SayT "Waiting for VPN Client" $1 "("$VPNTAG") to" $WSTATE"....."
  while [ $i -lt $TIMEOUT ]; do
    sleep 1
    #Say "Waiting for VPN Client" $1 "to" $WSTATE"....." $i
    if [ "$(nvram get "vpn_client"$1"_state")" = "$2" ]; then
      OK="1"
      break
    fi
    i=$(($i + 1))
  done
  if [ "$OK" = "1" ]; then
    echo -e $cBGRE"\t\tVPN Client" $1 "("$VPNTAG")" $WSTATE"'d in" $i "secs"$cRESET >&2
    SayT "VPN Client" $1 "("$VPNTAG")" $WSTATE"'d in" $i "secs"
  else
    echo -e $cBRED"\t\t***ERROR*** VPN Client" $1 "("$VPNTAG") FAILED to" $WSTATE "after" $i "secs"$cRESET >&2
    SayT "***ERROR*** VPN Client" $1 "("$VPNTAG") FAILED to" $WSTATE "after" $i "secs"
  fi
}
Get_VPN_ADDR() {

  local VPNADDRS=$(nvram show 2>/dev/null | grep -E "vpn_client.*addr" | grep -v t_addr)
  local VPN_ADDR=""

  for VPN in $VPNADDRS; do

    if [ "${VPN:10:1}" = "$1" ]; then
      VPN_ADDR=${VPN:17}
    #Say "***DEBUG ACTIVE VPN Client="$1 "via" $VPN_ADDR "VPN="$VPN
    #else
    #   Say "Get_VPN_ADDR():" $VPN ">" ${VPN:10:1} ">>" ${VPN:17}
    fi

  done

  echo $VPN_ADDR

}
HH_MM_in_Range() {
  local CURRENT_TIME=$(date +%H:%M)
  #local HH="$(echo $CURRENT_TIME | cut -d":" -f1)"
  #local MM="$(echo $CURRENT_TIME | cut -d":" -f2)"

  if [ "$CURRENT_TIME" \> "$1" ] && [ "$CURRENT_TIME" \< "$2" ]; then # Old style gotcha!
    #if [[ "$CURRENT_TIME" > "$1" ]] && [[ "$CURRENT_TIME" < "$2" ]]; then
    echo "Y"
    return 0
  else
    echo "N"
    return 1
  fi
}
Convert_1024KMG() {

  local NUM=$(echo "$1" | tr '[a-z]' '[A-Z]')

  if [ ! -z "$(echo $NUM | grep -oE "B|K|KB|M|MB|G|GB")" ]; then
    case "$(echo $NUM | grep -oE "B|K|KB|M|MB|G|GB")" in
      M | MB)
        local NUM=$(echo "$NUM" | tr -d 'MB')
        local NUM=$((NUM * 1024 * 1024))
        ;;
      G | GB)
        local NUM=$(echo "$NUM" | tr -d "GB")
        # local NUM=$((NUM*1024*1024*1024))
        local NUM=$(expr "$NUM" \* "1024" \* "1024" \* "1024")
        ;;
      K | KB)
        local NUM=$(echo "$NUM" | tr -d "KB")
        local NUM=$((NUM * 1024))
        ;;
      B)
        local NUM=$(echo "$NUM" | tr -d "B")
        ;;
    esac
  else
    NUM=$(echo "$NUM" | tr -dc '0-9')
  fi

  echo $NUM
}
Size_Human() {

  local SIZE=$1
  if [ -z "$SIZE" ]; then
    echo "N/A"
    return 1
  fi
  #echo $(echo $SIZE | awk '{ suffix=" KMGT"; for(i=1; $1>1024 && i < length(suffix); i++) $1/=1024; print int($1) substr(suffix, i, 1), $3; }')

  # if [ $SIZE -gt $((1024*1024*1024*1024)) ];then                                  # 1,099,511,627,776
  # printf "%2.2f TB\n" $(echo $SIZE | awk '{$1=$1/(1024^4); print $1;}')
  # else
  if [ $SIZE -gt $((1024 * 1024 * 1024)) ]; then # 1,073,741,824
    printf "%3.2f GB\n" $(echo $SIZE | awk '{$1=$1/(1024^3); print $1;}')
  else
    if [ $SIZE -gt $((1024 * 1024)) ]; then # 1,048,576
      printf "%3.2f MB\n" $(echo $SIZE | awk '{$1=$1/(1024^2);   print $1;}')
    else
      if [ $SIZE -gt $((1024)) ]; then
        printf "%3.2f KB\n" $(echo $SIZE | awk '{$1=$1/(1024);   print $1;}')
      else
        printf "%d Bytes\n" $SIZE
      fi
    fi
  fi
  # fi

  return 0
}
Update_VPN_Client() { # v1.10

  local THIS_VPN=$1
  local CURRENT_INDEX=$2

  local VPNSERVERADDR=
  local VPNPORT=
  local VPNPROTO=
  local THIS

  if [ "$CURRENT_INDEX" != "?" ]; then
    local USE_INDEX=$((CURRENT_INDEX + 1))
    if [ $USE_INDEX -gt $VPN_CONFIG_CNT ]; then
      local USE_INDEX=1
    fi

    local VPN_CONFIG_ACTIVE=$(nvram get vpn_client${THIS_VPN}_addr)":"$(nvram get vpn_client${THIS_VPN}_port)":"$(nvram get vpn_client${THIS_VPN}_proto)
    local VPNTAG=$(nvram get vpn_client${THIS_VPN}_desc)
  else
    local VPN_CONFIG_ACTIVE=$(nvram get vpn_client${VPN_ID}_addr)":"$(nvram get vpn_client${VPN_ID}_port)":"$(nvram get vpn_client${VPN_ID}_proto)
    local VPNTAG=$(nvram get vpn_client${VPN_ID}_desc)
  fi

  # Update the current VPN Client config to use a different server/port/protocol or return the current INDEX
  if [ -n "$VPN_CONFIGS" ]; then

    if [ $VPN_CONFIG_CNT -eq 1 ]; then
      echo "1" # '?' query so it must be INDEX 1 if only 1 entry!
      return
    fi

    local INDEX=0
    local OLDIFS=$IFS
    IFS="<"

    for CONFIG in $VPN_CONFIGS; do

      INDEX=$((INDEX + 1))

      if [ "$CURRENT_INDEX" != "?" ]; then # Is this an INDEX query?
        eval local VPNCONFIG${INDEX}=\$CONFIG
        [ $INDEX -eq $USE_INDEX ] && THIS=$CONFIG

      else
        if [ "$VPN_CONFIG_ACTIVE" == "$CONFIG" ]; then
          USE_INDEX=$INDEX # Found the current INDEX!!
        fi

      fi

    done
    IFS=$OLDIFS

    if [ "$CURRENT_INDEX" != "?" ]; then
      # Switch the config....
      Parse "$THIS" ":" VPNSERVERADDR VPNPORT VPNPROTO
      nvram set vpn_client${THIS_VPN}_addr="$VPNSERVERADDR"
      nvram set vpn_client${THIS_VPN}_port="$VPNPORT"
      nvram set vpn_client${THIS_VPN}_proto="$VPNPROTO" # Fix v1.10a

      # Tricky business of restoring ALL associated NVRAM variables and the three cert files 'ca,crt and key'   # v1.12
      # Should the script save a working NVRAM config when it requests and successfully starts a VPN Client?
      #     nvram show >2/dev/null | grep vpn_client5_ | sort >/jffs/openvpn/VPN_Failover/vpn_client5_NVRAM
      #
      # Read the NVRAM vars and restore 'em...

      # TBA

      # Since '/jffs/openvpn' holds the 'live' keys, use '/jffs/openvpn/VPN_Failover' to restore them
      if [ ! -f /jffs/openvpn/VPN_Failover ]; then
        cp -a /jffs/openvpn /jffs/openvpn/VPN_Failover # v1.12
      else
        # Now we can overwrite the target certs....                     # v1.11
        #cp -af /jffs/openvpn/VPN_Failover/vpn_crt_client${THIS_VPN}_ca  /jffs/openvpn/vpn_crt_client${THIS_VPN}_ca
        #cp  af /jffs/openvpn/VPN_Failover/vpn_crt_client${THIS_VPN}_crt /jffs/openvpn/vpn_crt_client${THIS_VPN}_crt
        #cp -af /jffs/openvpn/VPN_Failover/vpn_crt_client${THIS_VPN}_key /jffs/openvpn/vpn_crt_client${THIS_VPN}
        DUMMY=
      fi

      VPNDESC=$(awk -F# -v pattern="${VPNSERVERADDR}" 'match($0,pattern) {print $2}' /jffs/configs/VPN_Failover)
      [ -z "$VPNDESC" ] && VPNDESC="N/A $VPNSERVERADDR" # Fix v1.22
      nvram set vpn_client${THIS_VPN}_desc="$VPNDESC"   # Change the GUI
      echo -e $cBGRE"\t\tVPN Client" $1 "("$VPNTAG") Multi-config switching to Entry:" $USE_INDEX "of" $VPN_CONFIG_CNT "("$VPNSERVERADDR")" >&2
      SayT "VPN Client" $1 "("$VPNTAG") Multi-config switching to Entry:" $USE_INDEX "("$VPNSERVERADDR")"
    fi

    echo $USE_INDEX
  fi
}
#=============================================Main=============================================================
# shellcheck disable=SC2068
Main() { true; } # Syntax that is Atom Shellchecker compatible!

ANSIColours
# shellcheck disable=SC2068
SayT $VER "" $@

# Assistance required ?
if [ "$1" == "help" ] || [ "$1" == "-h" ]; then # Show help
  echo -e $cBWHT
  ShowHelp
  echo -e $cRESET
  exit 0
fi

MYROUTER=$(nvram get computer_name)

if [ -d "/tmp/mnt/"$MYROUTER ]; then
  MOUNT="/tmp/mnt/"$MYROUTER
else
  MOUNT="/tmp"
fi

METHOD=
IS_VPN_DOWN=0
IS_VPN_UP=2
ALARMBELL="\a"          # Console Audible ERRORS may be suppressed by using 'silent' directive

BLOCKEDPERIOD=0         # Apply restricted time periods
BLOCKED_PERIODS=        # Time window(s) when a VPN switch is NOT allowed e.g. 08:59-13:00,12:59-23:00
NOSWITCH=0              # 1-Allow VPN Client switching
VERBOSE=                # 'verbose=y' will generate additional cURL messages to console/Syslog
IGNORE_VPN=             # List of VPN Clients to ignore in round-robin
TIMEOUT=60              # Default VPN client start-up
INTERVAL=30             # Default interval cycle to check if VPN Client needs to be round-robin'd
VPN_ID=                 # Default VPN Client to Check
MULTI_VPNCONFIG_INDEX=0 # Used to track MULTI VPN config round-robin

FORCE_WGET=
FORCE_WGET_500B="http://proof.ovh.net/files/md5sum.txt"
FORCE_WGET_12MB="http://proof.ovh.net/files/100Mb.dat"
FORCE_WGET=
FORCE_OK=0
FORCE_WGET_MIN_RATE=0 # Minimum acceptable transfer rate in Bytes per second

MIN_CURLRATE_1=0 # Default VPN Client 1 - can be overridden by 'minrates=nnnnnn'
CURLSIZE1="NOCURL"

MIN_CURLRATE_2=0 # Default VPN Client 2 - can be overridden by 'minrates=?,nnnnnn'
CURLSIZE2="NOCURL"

MIN_CURLRATE_3=0 # Default VPN Client 3 - can be overridden by 'minrates=?,?,nnnnnn'
CURLSIZE3="NOCURL"

MIN_CURLRATE_4=0 # Default VPN Client 4 - can be overridden by 'minrates=?,?,?,nnnnnn'
CURLSIZE4="NOCURL"

MIN_CURLRATE_5=0 # Default VPN Client 5 - can be overridden by 'minrates=?,?,?,?,nnnnnn'
CURLSIZE5="NOCURL"

# First arg MUST be the VPN Client
if [ -n "$1" ] && [ -n "$(echo $1 | grep -oE "^[1-5]")" ]; then
  VPN_ID=$1
else
  SayT "**ERROR** VPN Client '"$1"' is INVALID (1-5 only)"
  echo -e $cBRED"\a\n\t**ERROR** VPN Client '"$1"' is INVALID (1-5 only)\n"
  #Say "Aborted!"
  echo -e "\n"$cRESET
  exit 99
fi

DEV="tun1"$VPN_ID

shift

while [ $# -gt 0 ]; do # Until you run out of parameters . . .
  case $1 in

    delay=*) # Allow the asyncronous call from openvpn-event vpnclientX-up to ensure that the VPN Client has fully initialised
      DELAY="$(echo "$1" | sed -n "s/^.*delay=//p")" # v1.08
      sleep $DELAY
      CMDDELAY=$DELAY
      ;;

    minrates=*) # Override the above '$MIN_CURLRATE_X' values if the 'minrates={n[.n]...}' is supplied  # v1.08

      VPN_CLIENT_RATES=$(echo "$1" | sed -n "s/^.*minrates=//p" | awk '{print $1}' | tr ',' ' ' | tr 'a-z' 'A-Z') # v1.09 allow 123k etc.

      if [ $(echo $VPN_CLIENT_RATES | wc -w) -gt 5 ]; then
        echo -en $cBRED"\a\n\t"
        SayT "***ERROR VPN Client minimum cURL rates 'minrates="$(echo "$@" | sed -n "s/^.*minrates=//p" | awk '{print $1}')"' INVALID! (must be max 5 CSV numeric values)"
        echo -e "***ERROR VPN Client minimum cURL rates 'minrates="$(echo "$@" | sed -n "s/^.*minrates=//p" | awk '{print $1}')"' INVALID! (must be max 5 CSV numeric values)\n" $cRESET
        exit 995
      fi

      INDEX=0
      for RATE in $VPN_CLIENT_RATES; do
        INDEX=$((INDEX + 1))
        [ "$RATE" == "?" ] && continue  # Ignore '?' placeholder
        RATE=$(Convert_1024KMG "$RATE") # Convert say 1M -> 1048576 Bytes
        if [ -n "${RATE##*[!0-9]*}" ]; then # Rate must be numeric
          eval MIN_CURLRATE_${INDEX}=\$RATE # Override the VPN Client default of 0
        else
          SayT "***ERROR VPN Client minimum cURL rates '$RATE' INVALID!"
          echo -e $cBRED"\a\n\t***ERROR VPN Client" $INDEX "new minimum cURL rate '$RATE' INVALID! (must be numeric)\n" $cRESET
          exit 995
        fi

      done
      CMDMINRATES=$VPN_CLIENT_RATES
      ;;

    verbose=*)
      VERBOSE="verbose" # Enable additional messages such as actual cURL transfer progress
      CMDVERBOSE=$VERBOSE
      ;;

    ignore=*) # v1.08
      IGNORE_VPN="$(echo "$1" | sed -n "s/^.*ignore=//p" | awk '{print $1}' | tr -d ',')" # Fix missing 'awk' v1.08a
      if [ -z "$IGNORE_VPN" ] || [ -n "$(echo "$IGNORE_VPN" | grep -E "[[:digit:]])")" ]; then
        echo -en ${cBRED}$ALARMBELL"\n\t"
        Say "***ERROR VPN configs 'ignore="$(echo "$1" | sed -n "s/^.*ignore=//p" | awk '{print $1}')"' INVALID! (must be CSV numeric 1-5)"
        echo -en $cRESET
        exit 996
      fi
      CMDIGNORE=$IGNORE_VPN
      SayT $CMDIGNORE
      ;;

    timeout=*)
      TIMEOUT="$(echo "$1" | sed -n "s/^.*timeout=//p" | awk '{print $1}' | grep -E "[[:digit:]]")"
      if [ -z "$TIMEOUT" ] || [ "$TIMEOUT" -gt 120 ]; then
        echo -en ${cBRED}$ALARMBELL"\n\t"
        Say "***ERROR VPN initialisation 'timeout="$(echo "$1" | sed -n "s/^.*interval=//p" | awk '{print $1}')"' INVALID! (must be numeric <=120 secs)"
        echo -en $cRESET
        exit 997
      fi
      CMDTIMEOUT=$TIMEOUT
      ;;

    interval=*)
      INTERVAL="$(echo "$1" | sed -n "s/^.*interval=//p" | awk '{print $1}' | grep -E "[[:digit:]]")"
      if [ -z "$INTERVAL" ] || [ "$INTERVAL" -gt 3600 ]; then
        echo -en ${cBRED}$ALARMBELL"\n\t"
        Say "***ERROR VPN initialisation 'interval="$(echo "$1" | sed -n "s/^.*interval=//p" | awk '{print $1}')"' INVALID! (must be numeric <=3600 secs)"
        echo -en $cRESET
        exit 998
      fi
      CMDINTERVAL=$INTERVAL
      ;;

    force | forcebig | forcesmall)
      # cURL transfer?....optionally requires 'curlrate='/'minrates' specification of MINIMUM acceptable transfer rate(s)
      if [ "$(echo $1 | grep -cw 'forcesmall')" -gt 0 ]; then
        FORCE_WGET=$FORCE_WGET_500B
        eval CURLSIZE$VPN_ID=$FORCE_WGET

      else
        FORCE_WGET=$FORCE_WGET_12MB
        eval CURLSIZE$VPN_ID=$FORCE_WGET
      fi
      METHOD=" using cURL data file retrieval"

      # Force ALL round-robin VPN Clients to use the same criteria
      CURLSIZE1=$FORCE_WGET
      CURLSIZE2=$FORCE_WGET
      CURLSIZE3=$FORCE_WGET
      CURLSIZE4=$FORCE_WGET
      CURLSIZE5=$FORCE_WGET

      CMDFORCE=$FORCE_WGET
      ;;

    curlrate=*)
      CMDCURLRATE=$(echo "$1" | sed -n "s/^.*curlrate=//p" | awk '{print $1}' | tr ',' ' ' | tr 'a-z' 'A-Z')

      if [ -z "$(echo "$CMDCURLRATE" | tr -dc '0-9')" ] || [ "$(echo "$CMDCURLRATE" | tr -dc '0-9')" -eq 0 ]; then
        echo -e ${cBRED}$ALARMBELL"\n\t***ERROR cURL rate MINIMUM '$1' cannot be 0/NULL\n"$cRESET
        exit 99
      else
        FORCE_WGET_MIN_RATE=$(Convert_1024KMG "$CMDCURLRATE")
      fi

      METHOD=" using MINIMIUM acceptable cURL transfer rate ("$FORCE_WGET_MIN_RATE" Bytes/sec)"
      eval MIN_CURLRATE_${VPN_ID}=\$FORCE_WGET_MIN_RATE # Restrict the cURL rate to the nominated VPN Client
      CMDCURLRATE=$FORCE_WGET_MIN_RATE
      ;;

    noswitch | noswitch=*)
      if [ "$1" == "noswitch" ]; then
        NOSWITCH=1 # Don't allow VPN Client switching; except if VPN Client DOWN
        CMDNOSWITCH=$1
      else
        BLOCKEDPERIOD=$(echo "$1" | sed -n "s/^.*noswitch=//p" | awk '{print $1}' | tr ',' ' ')

        for PERIOD in $BLOCKEDPERIOD; do
          # Split HH:MM-HH:MM
          TIME_PAIR=$(echo "$PERIOD" | tr '-' ' ')
          for TIME in $TIME_PAIR; do
            # Minimum must be 'HH:MM' format i.e. length 5
            case "${#TIME}" in
              #2)   [ $(echo "$TIME" | grep -oE "^([0-1][0-9])|^(2[0-3])$") ]               || { echo -e $cBRED"\a\n\t\t***ERROR '$TIME' (HH format) invalid\n"$cRESET;   exit 55; } ;;
              #3)   [ $(echo "$TIME" | grep -oE "^([0-1][0-9])|^(2[0-3])(:)?") ]            || { echo -e $cBRED"\a\n\t\t***ERROR '$TIME' (HH: format) invalid\n"$cRESET;  exit 66; } ;;
              5) [ $(echo "$TIME" | grep -oE "^([0-1][0-9])|^(2[0-3]):[0-5][0-9]$") ] || {
                echo -e $cBRED"\a\n\t\t***ERROR '$TIME' (HH:MM format) invalid\n"$cRESET
                exit 77
              } ;;
              *) {
                echo -e ${cBRED}$ALARMBELL"\n\t\tVPN switch blocked time period '$TIME' invalid format.\n"$cRESET
                exit 99
              } ;;
            esac
          done
        done
        BLOCKEDPERIOD=1 # Block VPN switching during the following periods
        BLOCKED_PERIODS=$BLOCKEDPERIOD
        CMDNOSWITCH=$BLOCKEDPERIOD
      fi
      ;;
    silent)
      ALARMBELL= # No audible console alert for ERRORS - except cmd arg validation
      CMDSILENT=$1
      SayT $CMDSILENT
      ;;
    multiconfig) # v.10
      CMDSERVERS=$1
      # Rather than rotate through the 5 VPN clients, use /jffs/configs/VPN_Failover to round-robin Server/port/protocol
      #        for unlimited servers from a VPN ISP
      # i.e.You could configure ALL 5 VPN Clients to the same provider which may not be appropriate.

      IGNORE_VPN=$(echo "1 2 3 4 5" | tr -d "$VPN_ID" | sed 's/^ //') # Use a single VPN Client

      #Say "Processing Server rotate config  file '/jffs/configs/VPN_Failover'"
      if [ -f '/jffs/configs/VPN_Failover' ]; then
        VPN_CONFIGS=$(awk -v pattern="${VPN_ID}" 'match($0,"^"pattern) {print $2,$3,$4}' /jffs/configs/VPN_Failover | tr '\n' '<' | tr ' ' ':' | sed 's/<$//')
        VPN_CONFIG_CNT=$(($(echo $VPN_CONFIGS | tr -dc '<' | wc -c) + 1))

        if [ -z $VPN_CONFIGS ]; then
          SayT "***ERROR VPN Client $VPN_ID NOT FOUND in Multi-config file '/jffs/configs/VPN_Failover'"
          echo -e ${cBRED}$ALARMBELL"\n\t***ERROR VPN Client $VPN_ID NOT FOUND in Multi-config file '/jffs/configs/VPN_Failover'\n"$cRESET
          exit 98
        fi
        # Identify the current ACTIVE config in the Multi-config file to set the INDEX to initiate the mult-config round-robin
        MULTI_VPNCONFIG_INDEX=$(Update_VPN_Client "$VPN_ID" "?")

        [ -z "$MULTI_VPNCONFIG_INDEX" ] && MULTI_VPNCONFIG_INDEX=1
      else
        SayT "***ERROR Multi-config file '/jffs/configs/VPN_Failover' NOT FOUND"
        echo -e ${cBRED}$ALARMBELL"\n\t***ERROR Multi-config file '/jffs/configs/VPN_Failover' NOT FOUND\n"$cRESET
        exit 99
      fi
      ;;
    once)
      CMDONCE=$1
      ONCE="once" # v1.11
      SayT $CMDONCE
      ;;
    *)
      echo -e ${cBRED}$ALARMBELL"\n\t***ERROR unrecognised directive '"$1"'\n"$cRESET
      exit 99
      ;;
  esac

  shift

done

# If SMDFORCE then CMDCURLRATE or CMDMINRATES MUST have been specified.
if [ -n "$CMDFORCE" ]; then
  if [ -z "$CMDCURLRATE" ]; then
    #echo -e ${cBRED}$ALARMBELL"\n\t***ERROR cURL transfer requested, but missing arg 'curlrate=' to define MINIMUM acceptable rate\n"$cRESET
    #exit 99
    DUMMY= # v1.09
  else
    if [ -z "$CMDMINRATES" ]; then
      echo -e ${cBRED}$ALARMBELL"\n\t*Warning VPN Client $VPN_ID cURL transfer requested, but no throughput rates will be checked for the other VPN Clients (use 'minrates=')\n"$cRESET
    fi
  fi
fi

# Ensure that if Multi-config requested that this DISABLES round-robin.
if [ -n "$VPN_CONFIGS" ]; then
  echo -e ${cBRED}$ALARMBELL"\n\t*Warning VPN Client $VPN_ID Multi-config Entry:" $MULTI_VPNCONFIG_INDEX" of "$VPN_CONFIG_CNT"; Round-robin of VPN Clients DISABLED (ignore='$IGNORE_VPN' ENFORCED) \n"$cRESET
  IGNORE_VPN=$(echo "1 2 3 4 5" | tr -d "$VPN_ID") # Use a single VPN Client
fi

# Loop forever and check VPN Client status every (default) 30 secs or $INTERVAL value specified by user e.g. 'interval=60'
while true; do

  TRACKFILE="${MOUNT}/vpnclient$VPN_ID"
  LOCKFILE=$TRACKFILE"-monitor"

  echo $$ >$LOCKFILE

  #SayT "VPN Client Monitor: Starting.....(using '"$LOCKFILE"')"
  #echo -e $cBYEL"\n\t$VER VPN Client Monitor: Starting.....\n"
  echo -e

  case "$VPN_ID" in # v1.08
    1)
      FORCE_WGET_MIN_RATE=$MIN_CURLRATE_1 # The cURL rate specific to a VPN for file transfer...
      FORCE_WGET=$CURLSIZE1               # The cURL file to be measured
      ;;
    2)
      FORCE_WGET_MIN_RATE=$MIN_CURLRATE_2 # The cURL rate specific to a VPN for file transfer...
      FORCE_WGET=$CURLSIZE2               # The cURL file to be measured
      ;;
    3)
      FORCE_WGET_MIN_RATE=$MIN_CURLRATE_3 # The cURL rate specific to a VPN for file transfer...
      FORCE_WGET=$CURLSIZE3               # The cURL file to be measured
      ;;
    4)
      FORCE_WGET_MIN_RATE=$MIN_CURLRATE_4 # The cURL rate specific to a VPN for file transfer...
      FORCE_WGET=$CURLSIZE4               # The cURL file to be measured
      ;;
    5)
      FORCE_WGET_MIN_RATE=$MIN_CURLRATE_5 # The cURL rate specific to a VPN for file transfer...
      FORCE_WGET=$CURLSIZE5               # The cURL file to be measured
      ;;
  esac

  if [ $FORCE_WGET_MIN_RATE -eq 0 ]; then
    METHOD= # If no cURL rate threshold then clear the header message
  else
    METHOD=" using MINIMIUM acceptable cURL transfer rate ("$FORCE_WGET_MIN_RATE" Bytes/sec)"
  fi

  SayT "VPN Client Monitor: Checking VPN Client" $VPN_ID "connection status...." $METHOD
  echo -e $cBYEL"\t"$(date +"%H:%M:%S") $VER "VPN Client Monitor: Checking VPN Client" $VPN_ID "connection status...." $METHOD "\n"

  # Check if VPN isn't UP or performance is unacceptably 'SLOW'
  PERFORMANCE=$(Check_VPN "CURL" "$FORCE_WGET" "$VPN_ID" "quiet") # v1.08

  if [ "$(nvram get "vpn_client"${VPN_ID}"_state")" != "$IS_VPN_UP" ] || [ "$PERFORMANCE" == "FAIL" ]; then
    case "$VPN_ID" in
      1) NEW_VPN_ID=2 ;; # VPN Client 1 is DOWN or 'slow'?; Switch to VPN Client 2;;
      2) NEW_VPN_ID=3 ;; # VPN Client 2 is DOWN or 'slow'?; Switch to VPN Client 3
      3) NEW_VPN_ID=4 ;; # VPN Client 3 is DOWN or 'slow'?; Switch to VPN Client 4
      4) NEW_VPN_ID=5 ;; # VPN Client 4 is DOWN or 'slow'?; Switch to VPN Client 5
      5) NEW_VPN_ID=1 ;; # VPN Client 5 is DOWN or 'slow'?; Switch to VPN Client 1
    esac

    # Get current VPN STATE?
    VPNSTATE="$(nvram get "vpn_client"${VPN_ID}"_state")"
    case $VPNSTATE in
      0) REASON=$VPNSTATE";Disconnected" ;;
      1) REASON=$VPNSTATE";Connecting" ;;
      2)
        REASON=$VPNSTATE";Connected"
        [ "$PERFORMANCE" == "FAIL" ] && REASON=$REASON" but SLOW!"
        ;;
      "-1") REASON=$VPNSTATE";Unknown Error - Password/routing issue?" ;;
      *) REASON=$VPNSTATE";?" ;;
    esac

    if [ "$VPNSTATE" != "$IS_VPN_DOWN" ]; then
      # VPN State is UP i.e. 'Connected but SLOW', 'Connecting' or 'Disconnecting' or in 'Error', so stop it anyway?

      # If the VPN Client was taken down because it is SLOW simply restart it?  # v1.08
      if [ -n "$(echo "$REASON" | grep -F "SLOW")" ]; then
        if [ "$DISABLEROUNDROBIN" == "Y" ]; then
          NEW_VPN_ID=$VPN_ID # Temporary TBA
          REASON=$REASON". Round robin DISABLED - cURL rate inappropriate for other VPN Clients"
        fi
      fi

      # Limit the VPN switching/restart to a time window?       # v1.09
      # i.e. just because it's SLOW, this might be acceptable overnight to critical file transfers continue albeit at a trickle?
      # although if it's the middle of the day then surely you need to take the hit immediately?
      if [ -n "$BLOCKED_PERIODS" ]; then
        BLOCKED_PERIODS=$(echo $BLOCKED_PERIODS | tr ',' ' ')
        for PERIOD in $BLOCKED_PERIODS; do
          FROM=$(echo $PERIOD | cut -d'-' -f1)
          TO=$(echo $PERIOD | cut -d'-' -f2)
          #Say "***DEBUG PERIOD="$PERIOD "FROM=>"$FROM"< TO >"$TO"<"
          if [ "$(HH_MM_in_Range "$FROM" "$TO")" == "Y" ]; then
            NOSWITCH=1 # Prevent VPN Client switching
            break
          fi
        done
      fi

      if [ $NOSWITCH -eq 1 ]; then # v1.09
        if [ -n "$PERIOD" ]; then
          SayT "VPN Client switch is PERIOD restricted ("$BLOCKED_PERIODS")"
          echo -e $cCYA"\t\tVPN Client" $VPN_ID "switch to VPN Client" $NEW_VPN_ID "(Reason: VPN Client" $VPN_ID "STATE=${REASON}) is PERIOD restricted ("$BLOCKED_PERIODS")"
        else
          SayT "VPN Client switching is explicitly DISABLED ('noswitch')"
          echo -e $cCYA"\t\tVPN Client" $VPN_ID "switch to VPN Client" $NEW_VPN_ID "(Reason: VPN Client" $VPN_ID "STATE=${REASON}) is explicitly DISABLED ('noswitch')"
        fi

        SayT "VPN Client Monitor: VPN Client" $VPN_ID "status tolerated OK"
        echo -e $cGRE"\t\tVPN Client" $VPN_ID "connection is deemed throughput/performance degraded but tolerated... OK"
      else
        #Say "VPN Client switch is NOT PERIOD restricted ("$BLOCKED_PERIODS")"

        SayT "**VPN Client Monitor: Switching VPN Client" $VPN_ID "to VPN Client" $NEW_VPN_ID "(Reason: VPN Client" $VPN_ID "STATE=${REASON})"
        SayT "**VPN Client Monitor: Terminating VPN Client" $VPN_ID
        echo -e $cBCYA"\t\tSwitching VPN Client" $VPN_ID "to VPN Client" $NEW_VPN_ID "(Reason: VPN Client" $VPN_ID "STATE=${REASON})"
        echo -e ${cBRED}$ALARMBELL"\t\tTerminating VPN Client" $VPN_ID

        # Prevent vpnclientX-route-pre-down from terminating this script
        echo "NOKILL" >$LOCKFILE                                 # v1.15
        RC=$(service stop_vpnclient${VPN_ID})

        Check_VPNState $VPN_ID $IS_VPN_DOWN

        NEXTVPN="Y" # Override 'noswitch' i.e. ensure that a VPN is ALWAYs started if VPN is DOWN
      fi

    else
      # VPN State is 'Disconnected'
      SayT "**VPN Client Monitor: Switching VPN Client" $VPN_ID "to VPN Client" $NEW_VPN_ID "(Reason: VPN Client" $VPN_ID "STATE=${REASON})"
      echo -e $cBCYA"\t\tSwitching VPN Client" $VPN_ID "to VPN Client" $NEW_VPN_ID "(Reason: VPN Client" $VPN_ID "STATE=${REASON})"

      NEXTVPN="Y" # Override 'noswitch' i.e. ensure that a VPN is ALWAYs started if VPN Client is DOWN
    fi

    if [ -n "$NEXTVPN" ] || [ $NOSWITCH -eq 0 ]; then

      # Check if the target VPN client is ACTUALLY configured...                v1.07
      VPN_NO_SLEEP=
      VPN_ADDR=$(Get_VPN_ADDR $NEW_VPN_ID)
      if [ -z "$VPN_ADDR" ]; then
        echo -e $cRED
        SayT "*Warning VPN Client" $NEW_VPN_ID "not configured? - auto IGNORED/SKIPPED"
        echo -e "\t\t*Warning VPN Client" $NEW_VPN_ID "not configured? - auto IGNORED/SKIPPED"
        VPN_NO_SLEEP="NO CONFIG" # Indicate that the $INTERVAL wait time should be skipped...
      else

        # Don't attempt to start VPN Client if specifically in "ignore=n,n,n"
        if [ -z "$(echo "$IGNORE_VPN" | grep -oF "$NEW_VPN_ID")" ]; then

          # Multiple VPN configs require dynamic modification of
          if [ -n "$VPN_CONFIGS" ]; then
            # Use the next round-robin config.....
            MULTI_VPNCONFIG_INDEX=$(Update_VPN_Client "$NEW_VPN_ID" "$MULTI_VPNCONFIG_INDEX")
          fi

          RC=$(service start_vpnclient${NEW_VPN_ID}) # Fix use 'start_' rather than 'restart_' v1.08

          # Allow for VPN Client to connect
          Check_VPNState $NEW_VPN_ID $IS_VPN_UP

          if [ "$(nvram get "vpn_client"${NEW_VPN_ID}"_state")" != "$IS_VPN_UP" ]; then

            # Now this could have serious consequences, i.e VPNBOOK won't start if password expired,
            #     but clearly it won't disconnect as 'vpn_client3_state=-1'
            #     Shouldn't be a problem right?, yet sometimes no other VPN Clients will start!!! until the flag is
            #     reset i.e. 'nvram set vpn_client3_state=0'
            if [ "$(nvram get "vpn_client"$NEW_VPN_ID"_state")" == "-1" ]; then # v1.09
              SayT "***ERROR VPN Client Monitor: VPN Client" $NEW_VPN_ID "FAILED to start (nvram  vpn_client${NEW_VPN_ID}_state reset)"
              echo -e ${cBRED}${aBLINK}$ALARMBELL"\n\n\t\t***ERROR VPN Client Monitor: VPN Client" $NEW_VPN_ID "FAILED to start (vpn_client${NEW_VPN_ID}_state=-1 reset)\n"$cRESET
              nvram set vpn_client${NEW_VPN_ID}_state="0" # v1.09
            fi

            VPN_ID=$NEW_VPN_ID # v1.06 Force round-robin
            DEV="tun1"$VPN_ID
            #exit 99
            continue
          else
            NEXTVPN= # Reset the override i.e. 'noswitch' will now be honoured!
          fi
        else
          echo -e $cRED
          SayT "*Warning Configured VPN Client" $NEW_VPN_ID " - Manually set to be IGNORED/SKIPPED"
          echo -e "\t\t*Warning Configured VPN Client" $NEW_VPN_ID "- Manually set to be IGNORED/SKIPPED"
          VPN_NO_SLEEP="IGNORE" # Indicate that the $INTERVAL wait time should be skipped...
        fi
      fi

      VPN_ID=$NEW_VPN_ID
      DEV="tun1"$VPN_ID
    fi
  else
    SayT "VPN Client Monitor: VPN Client" $VPN_ID "status OK"
    echo -e $cBGRE"\t\tVPN Client" $VPN_ID "connection status OK"
    echo $$ >$LOCKFILE                          # v1.15 Allow vpnclientX-route-pre-down to terminate this script by PID
    if [ -n "$ONCE" ]; then # v1.11.1
      SayT "VPN Client Monitor: Monitoring VPN Client" $VPN_ID "terminated"
      echo -e $cBYEL"\n\t"$(date +"%H:%M:%S")" $VER VPN Client Monitor: Monitoring VPN Client" $VPN_ID "terminated\n"
      exit 0
    fi
  fi

  if [ -z "$VPN_NO_SLEEP" ]; then # v1.07
    echo -e $cBYEL"\n\t\tWill check VPN Client" $VPN_ID "connection status again in" $INTERVAL "secs.....@"$(date -D '%s' -d "$(($(date +%s) + $INTERVAL))" +"%H:%M:%S") # v1.08
    sleep $INTERVAL
  else
    VPN_NO_SLEEP=
  fi

  # Check for external kill switch
  if [ ! -f $LOCKFILE ]; then
    SayT "VPN Client Monitor: Monitoring VPN Client" $VPN_ID "terminated ('"$LOCKFILE"' not found)"
    echo -e $cBYEL"\t\t"$(date +"%H:%M:%S")" Monitoring VPN Client" $VPN_ID "terminated ('"$LOCKFILE"' not found)\n"$cRESET
    break
  fi

done

echo -e $cRESET

exit 0
