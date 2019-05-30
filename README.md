# VPN-Failover
ASUS Router Monitor VPN Client connection status/thoughput performance and switch or restart VPN Client

This script can monitor the connection status of a VPN Client interface, and if the status is found to be unacceptable, can perform one of the following:

		1. Report on the status of the nominated VPN Client connection
		2. Restart the VPN Client
		3. Start a different VPN Client configuration
		4. Restart the same VPN Client instance with a different server/port/protocol*
		
The script will attempt to use cURL to retrieve data via the VPN Client tunnel except in the case of site-site VPN tunnel where the remote site has enabled 'LAN ONLY', in which case you will need to specify the 'pingonly=' directive to use PING rather than cURL to determine the state of the connection.

The easiest method (to implement the script) to monitor a VPN Client connection is to simply use cru (cron) schedule(s)

e.g. Every 60 minutes @5 minutes past the hour, check the state of the VPN Client 1

		cru "5 */1 * * *" /jffs/scripts/VPN_Failover.sh  1 once
			
However, using a static schedule, isn't very flexible, as suppose the VPN Client is legitimately DOWN, then unless the cru (cron) schedule is stopped, the VPN Client connection will be restored, which may be inappropriate.

A better solution is to only enable the monitoring when the VPN Client is manually started, and to cease monitoring when the VPN Client is manually terminated.
This method will require the openvpn-event triggers vpnclientX-route-up/vpnclientX-up and vpnclientX-route-pre-down scripts to be implemented.

e.g. 2 minutes after VPN Client 1 is started, monitor the status of VPN Client 1, every 60 minutes
	
		/jffs/scripts/vpnclient1-route-pre-up
		
		VPN_ID=${dev:4:1}
		logger -st "($(basename $0))" $$ "Requesting VPN Failover monitor with 2 min delay....."
		/jffs/scripts/VPN_Failover.sh "$VPN_ID" "delay=120" "interval=3600" &

and subsequently needs to be terminated by openvpn-event vpnclientX-route-pre-down (unless the termination is requested by this script)

		/jffs/scripts/vpnclient1-route-pre-down
		
		VPN_ID=${dev:4:1}
		VPNFAILOVER="/tmp/vpnclient"$VPN_ID"-VPNFailover"
		# Also rely on the VPN_Failover.sh to test for the existence of the VPNFailover semaphore BEFORE it attempts a restart!
		if [ -z "$(grep "NOKILL" $VPNFAILOVER)" ];then
			PID=$(cat $VPNFAILOVER)
			[ "$PID" != "NOKILL" ] && kill $PID
			rm $VPNFAILOVER
			logger -st "($(basename $0))" $$ "VPN Failover Monitor self-destruct requested....." $VPNFAILOVER "RC="$?  # RC=1 means file was already deleted
		fi

OpenVPN is quite capable of monitoring its connection, and can automatically restart with a different server/port/protocol by including the appropriate directives.

One unique feature of the script is its ability to measure the time taken for a data transfer to occur, and (if convenient) restart the connection.

	e.g. If the 433Byte cURL transfer rate is <1000 Bytes per second, no (disruptive) VPN Switch is performed during 'office' hours 9-5

	./VPN_Failover 3 forcesmall curlrate=1000 verbose noswitch=08:59-17:00

The complete list of command options may be retrieved using
  
	VPN_Failover.sh help

		#======================================================================================================= © 2016-2019 Martineau, v1.17
		#
		# Check every 30 secs, and switch to alternate VPN Client if current VPN Client is DOWN, or expected cURL data transfer is 'SLOW'
		#
		#          VPN_Failover   [-h | help | status ] |
		#						  {vpn_instance to monitor} [ignore='csv_vpn_clients] [interval='seconds'] [timeout='seconds']] [force[big | small]
		#                         [curlrate='number'] [minrates='csv_rates'] [verbose] [delay='seconds'] [noswitch[='hhmm-hhmm'[,...]]] [silent] 
		#                         [multiconfig] [once] [pingonly=ping_target] [sendmail]
		#
		#          VPN_Failover   1
		#                         Monitor VPN Client 1 every 30 secs and if DOWN switch to VPN Client 2 and then monitor VPN Client 2
		#                         (This initiates the round robin for ALL VPN Clients (if configured) in sequence 2,3,4,5 then back to VPN Client 1)
		#          VPN_Failover   1 once
		#                         As above, but the script terminates immediately and exits if the VPN Client 1 connection is UP.
		#          VPN_Failover   status
		#                         Show the status of ACTIVE monitoring processes and the semaphores '/tmp/vpnclientX-VPNFailover'
		#          VPN_Failover   2 ignore=3,4,5
		#                         Monitor VPN Client 2 every 30 secs and if DOWN switch to VPN Client 1 and then monitor VPN Client 1
		#                         (This initiates the round robin ONLY for the two VPN Clients; VPN1 (Primary) and VPN2 (Fail-over)
		#          VPN_Failover   2 interval=60
		#                         Monitor VPN Client 2 every 60 secs and if DOWN switch to VPN Client 3 and then monitor VPN Client 3
		#          VPN_Failover   5 delay=45
		#                         Monitor VPN Client 5 every 30 secs and if DOWN switch to VPN Client 1 and allow max 45 secs for Client 1 to start
		#                         then monitor VPN Client 1
		#          VPN_Failover   4 pingonly=10.99.8.1
		#                         Client 4's OpenVPN Server, may have 'LANONLY', so a cURL to retrieve the VPN exit-IP will not work, so instead
		#                         force the test to use only PING. (NOTE: The ping target will normally be the remote router (nvram get lan_ipaddr))
		#          VPN_Failover   3 force curlrate=1M
		#                         If the 12MB cURL transfer rate is <1048576 Bytes per second, then treat this as VPN Client 3 'DOWN'
		#                         (This cURL rate is not applicable to other VPN Clients if a switch occurs)
		#          VPN_Failover   3 force curlrate=1M verbose
		#                         As previous example, but additional cURL transfer statistics/progress messages are shown on the console. (Useful to determine appropriate 'minrates=')
		#          VPN_Failover   3 forcesmall curlrate=1000 verbose noswitch=08:59-17:00
		#                         If the 433Byte cURL transfer rate is <1000 Bytes per second, no (disruptive) VPN Switch is performed during 'office' hours 9-5
		#          VPN_Failover   3 forcesmall curlrate=1000 verbose noswitch
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



Installation

Enable SSH on router, then use your preferred SSH Client e.g. Xshell6,MobaXterm, PuTTY etc. to copy'n'paste:

	curl --retry 3 "https://raw.githubusercontent.com/MartineauUK/VPN-Failover/master/VPN_Failover.sh" -o "/jffs/scripts/VPN_Failover.sh" && chmod 755 "/jffs/scripts/VPN_Failover.sh"
	
You may check the status of the script monitoring

	./VPN_Failover status
