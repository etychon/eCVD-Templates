<#if far.isRunningIos()>
<#-- Enable periodic inventory notification every 30 mins to report metrics. -->
    cgna profile cg-nms-periodic
      no active
      interval 30
      active
    exit
<#-- Enable periodic configuration (heartbeat) notification every 10 mins. -->
   cgna heart-beat interval 10

   event manager directory user policy "flash:/managed/scripts"

<#-- Begin eCVD template -->
<#-- Version 1.72        -->

<#-- Default BootStrap Configuration -->

<#assign sublist 		= "${far.eid}"?split("+")[0..1]>
<#assign pid = sublist[0]>
<#assign model = pid[0..4]>
<#assign sn = sublist[1]>

<#assign model = "IR1101">

<#-- Interface Menu - which Ethernet interfaces are enabled? -->
<#assign FastEthernet1_enabled = far.fastEthernet1!"true">
<#assign FastEthernet2_enabled = far.fastEthernet2!"true">
<#assign FastEthernet3_enabled = far.fastEthernet3!"true">
<#assign FastEthernet4_enabled = far.fastEthernet4!"true">

<#-- PLATFORM SPECIFIC VARIABLES -->
<#assign ether_if = "GigabitEthernet 0/0/0">
<#assign cell_if1 = "Cellular 0/1/0">
<#assign vpnTunnelIntf = "Tunnel2">

<#assign ipslaDestIPaddress = ["4.2.2.1","4.2.2.2"]>


<#-- VARIABLES INITIALIZATION -->
<#assign highestPriorityIfName = 1>
<#assign priorityIfNameTable = []>
<#assign isTunnelEnabledTable = []>
<#assign EthernetPortPriority = 200>
<#assign Cell1PortPriority = 200>
<#assign isCellIntTable = []>


<#-- WAN Menu -->

<#if section.wan_ethernet?has_content && section.wan_ethernet == "true">
  <#assign isEthernetEnable = "true">
<#else>
  <#assign isEthernetEnable = "false">
</#if>

<#if section.wan_cellular1?has_content && section.wan_cellular1 == "true">
  <#assign isFirstCell = "true">
  <#if far.apn1?has_content>
    <#assign APN1			= "${far.apn1}">
  </#if>
  <#-- TODO: this will need to change to support LTE modules
  with no GPS support. Use far...isGpsEnabled toggle in updated
  UPT version 1.14 -->
  <#if far.cellFirmwareVersion1?has_content && far.cellFirmwareVersion1?starts_with("SWI")>
    <#-- taking wild guess that if Sierra Wireless firmware it
       probably has GPS capability. -->
    <#assign isGpsEnabled = "true">
  <#else>
    <#assign isGpsEnabled = "false">
  </#if>
<#else>
    <#assign isFirstCell = "false">
</#if>




<#-- LAN Menu -->
<#assign lanIP 		= "${far.lanIPAddress}"?split(".")>
<#assign lanNet 	= "${far.lanNetmask}"?split(".")>

<#-- Network Menu -->

<#-- VPN Settings Menu -->
<#assign isPrimaryHeadEndEnable = "false">
<#assign isSecondaryHeadEndEnable = "false">
<#if !section.vpn_primaryheadend?? || section.vpn_primaryheadend == "true">
  <#if far.herIpAddress?has_content && far.herPsk?has_content>
    <#assign herIpAddress 	= "${far.herIpAddress}">
    <#assign herPsk			    = "${far.herPsk}">
    <#assign isPrimaryHeadEndEnable = "true">
  </#if>
  <#if !section.vpn_backupheadend?? || section.vpn_backupheadend == "true">
    <#if far.backupHerIpAddress?has_content && far.backupHerPsk?has_content>
      <#assign backupHerIpAddress = "${far.backupHerIpAddress}">
      <#assign backupHerPsk	= "${far.backupHerPsk}">
      <#assign isSecondaryHeadEndEnable = "true">
    </#if>
  </#if>
</#if>

<#-- Device Settings Menu -->
<#if far.localDomainName?has_content>
<#assign domainName = "${far.localDomainName}">
<#else>
<#assign domainName = "local">
</#if>
<#-- Assign Umbrella DNS servers for additional Security -->
<#assign DNSIP		= "208.67.222.222 208.67.220.220">

<#if far.clockTZ?has_content>
<#assign clockTZ 	= "${far.clockTZ}">
<#else>
<#assign clockTZ	= "edt">
</#if>
<#-- assign clockDST	= "${far.clockDST}"-->
<#if far.ntpIP?has_content>
<#assign ntpIP 		= "${far.ntpIP}">
<#else>
<#assign ntpIP		= "time.nist.gov">
</#if>

<#-- Calculate Netmasks -->

<#function ipv4_to_binary ipaddr>
  <#assign bin_ip=[]>
  <#list ipaddr as lann>
    <#assign lan=lann?number>
    <#list 1..100 as y>
      <#if lan < 1 >
        <#if lan == 0>
          <#list 1..8 as s>
            <#assign bin_ip=bin_ip+["0"]>
          </#list>
	      </#if>
        <#if bin_ip?size % 8 != 0>
          <#list 1..8 as s>
	          <#assign bin_ip=bin_ip+["0"]>
	          <#if bin_ip?size % 8 == 0>
	            <#break>
            </#if>
	        </#list>
	      </#if>
        <#break>
      </#if>
      <#assign x=lan%2 st=x?string bin_ip=bin_ip+[st] lan=lan/2>
    </#list>
  </#list>
  <#return (bin_ip)>
</#function>

<#assign  lan_ip=[]  lan_netmask=[]>

<#-- Binary Conversion of LAN IP-->

<#assign lan_ip=ipv4_to_binary(lanIP)>
<#assign ip_bit = lan_ip?reverse>
<#assign lan_netmask=ipv4_to_binary(lanNet)>
<#assign subnet_bit=lan_netmask?reverse>

<#-- Logical AND operation between IP and NetMask-->

<#assign lan_netID=[]>
<#list ip_bit as rev_index>
<#if rev_index?string == "1" && subnet_bit[rev_index?index] == "1"><#assign lan_netID=lan_netID+["1"]></#if>
<#if rev_index?string == "1" && subnet_bit[rev_index?index] == "0"><#assign lan_netID=lan_netID+["0"]></#if>
<#if rev_index?string == "0" && subnet_bit[rev_index?index] == "1"><#assign lan_netID=lan_netID+["0"]></#if>
<#if rev_index?string == "0" && subnet_bit[rev_index?index] == "0"><#assign lan_netID=lan_netID+["0"]></#if>
</#list>
<#assign netid_bit=lan_netID?reverse>

<#--Binary to Decimal conversion of Logical AND product-->

<#assign netid=[]>
<#list netid_bit?chunk(8) as row> <#assign num=0 pow=1> <#list row as bit> <#assign num=num+pow*bit?number pow=pow*2> </#list>
<#assign netid=netid+[num]>
</#list>

<#--Network Address-->

<#assign lanNtwk = netid?join(".")?string>
<#assign lanWild = "${(255 - (lanNet[0])?number)?abs}.${(255 - (lanNet[1])?number)?abs}.${(255 - (lanNet[2])?number)?abs}.${(255 - (lanNet[3])?number)?abs}">

<#-- Configure timezone offset -->

<#assign TZ = { "anat":"+12", "sbt":"+11", "aest":"+10", "jst":"+9", "cst":"+8", "wib":"+7", "bst":"+6", "uzt":"+5", "gst":"+4", "msk":"+3", "cest":"+2", "bst":"+1", "gmt":"0", "cvt":"-1", "wgst":"-2", "art":"-3", "edt":"-4", "cdt":"-5", "mst":"-6", "pdt":"-7", "akdt":"-8", "hdt":"-9", "hst":"-10", "nut":"-11", "aeo":"-12" }>
<#list TZ as x, y >
	<#if x != clockTZ>
		<#continue>
	<#else>
		<#assign offset = y>
	</#if>
</#list>

<#-- Configure Device Settings -->

service tcp-keepalives-in
service tcp-keepalives-out
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
service call-home
platform qfp utilization monitor load 80
no platform punt-keepalive disable-kernel-core
!
no logging console
!
clock timezone ${clockTZ} ${offset}
ntp server ${ntpIP}
!
ip name-server ${DNSIP}
ip domain name ${domainName}

<#if far.lanIPAddressDHCPexcludeRangeStart?has_content && far.lanIPAddressDHCPexcludeRangeEnd?has_content>
ip dhcp excluded-address ${far.lanIPAddressDHCPexcludeRangeStart} ${far.lanIPAddressDHCPexcludeRangeEnd}
</#if>
!

ip dhcp pool subtended
    network ${lanNtwk} ${far.lanNetmask}
    default-router ${far.lanIPAddress}
    dns-server ${DNSIP}
    lease 0 0 10
!
!
<#list far.Users as user >
		username ${user['userName']} privilege ${user['userPriv']} algorithm-type scrypt secret ${user['userPassword']}
</#list>
!
<#-- S2S VPN Configuration -->
!
<#if !section.vpn_primaryheadend?? || section.vpn_primaryheadend == "true">

crypto ikev2 authorization policy CVPN
 	route set interface
 	route accept any distance 70
!
crypto ikev2 keyring Flex_key
!
 peer ${herIpAddress}
  address ${herIpAddress}
  identity key-id ${herIpAddress}
  pre-shared-key ${herPsk}
!
<#if !section.vpn_backupheadend?? || section.vpn_backupheadend == "true">
  peer ${backupHerIpAddress}
  address ${backupHerIpAddress}
  identity key-id ${backupHerIpAddress}
  pre-shared-key ${backupHerPsk}
!
</#if>
!
!
crypto ikev2 profile CVPN_I2PF
 match identity remote key-id ${herIpAddress}
<#if !section.vpn_backupheadend?? || section.vpn_backupheadend == "true">
  match identity remote key-id ${backupHerIpAddress}
</#if>
 identity local email ${sn}@iotspdev.io
 authentication remote pre-share
 authentication local pre-share
 keyring local Flex_key
 dpd 29 2 periodic
 aaa authorization group psk list CVPN CVPN
!
!
crypto ipsec profile CVPN_IPS_PF
 set ikev2-profile CVPN_I2PF
!
!
interface Tunnel2
 ip address negotiated
 ip mtu 1358
 ip nat outside
 ip tcp adjust-mss 1318
 tunnel source dynamic
 tunnel mode ipsec ipv4
 tunnel destination dynamic
 tunnel path-mtu-discovery
 tunnel protection ipsec profile CVPN_IPS_PF
!
!
crypto ikev2 client flexvpn Tunnel2
  peer 1 ${herIpAddress}
<#if !section.vpn_backupheadend?? || section.vpn_backupheadend == "true">
  peer 2 ${backupHerIpAddress}
</#if>
  client connect Tunnel2
!
!
</#if>
!

<#-- Enable GPS  -->
<#if isFirstCell == "true" && isGpsEnabled?has_content && isGpsEnabled == "true">
controller ${cell_if1}
 	lte gps mode standalone
  lte gps nmea
</#if>
!

interface ${ether_if}
    media-type rj45
    no shutdown
    ip nat outside
!
!
interface ${cell_if1}
    ip address negotiated
    ip nat outside
    dialer in-band
    dialer idle-timeout 0
    dialer-group 1
    pulse-time 1
!
!
interface Vlan1
    ip address ${far.lanIPAddress} ${far.lanNetmask}
    ip nbar protocol-discovery
    ip nat inside
    ip verify unicast source reachable-via rx
!
!

<#-- enabling/disabling of ethernet ports -->

interface FastEthernet0/0/1
<#if FastEthernet1_enabled != "true">
    shutdown
<#else>
	no shutdown
</#if>
!
interface FastEthernet0/0/2
<#if FastEthernet2_enabled != "true">
    shutdown
<#else>
	no shutdown
</#if>
!
interface FastEthernet0/0/3
<#if FastEthernet3_enabled != "true">
    shutdown
<#else>
	no shutdown
</#if>
!
interface FastEthernet0/0/4
<#if FastEthernet4_enabled != "true">
    shutdown
<#else>
	no shutdown
</#if>

interface Async0/2/0
    no ip address
    encapsulation scada
!

<#-- Enable IOx -->
iox


<#-- Use default i/f to set PAT -->

<#if far.portForwarding?has_content>
<#list far.portForwarding as PAT>
  <#if PAT['protocol']?has_content>
  <#if EthernetPortPriority == 101>
        ip nat inside source static ${PAT['protocol']} ${PAT['privateIP']} ${PAT['localPort']} interface ${ether_if} ${PAT['publicPort']}
  <#else>
     <#if isFirstCell == "true">
      ip nat inside source static ${PAT['protocol']} ${PAT['privateIP']} ${PAT['localPort']} interface ${cell_if1} ${PAT['publicPort']}
     </#if>
  </#if>
  </#if>
</#list>
</#if>

<#-- remove this route from the bootstrap config to allow failover -->
<#if isFirstCell == "true">
  no ip route 0.0.0.0 0.0.0.0 ${cell_if1} 100
</#if>

<#list 1..4 as p>
  <#if isEthernetEnable == "true"
        && ether_if?? && far.ethernetPriority?has_content
        && far.ethernetPriority == p?string>
    <#assign priorityIfNameTable += [ether_if]>
    <#assign isTunnelEnabledTable += [far.enableTunnelOverEthernet!"false"]>
    <#assign isCellIntTable += ["false"]>
    <#assign EthernetPortPriority = 100+p>
  <#elseif isFirstCell == "true"
        && cell_if1?? && far.firstCellularIntPriority?has_content
        && far.firstCellularIntPriority == p?string>
    <#assign priorityIfNameTable += [cell_if1]>
    <#assign isTunnelEnabledTable += [far.enableTunnelOverCell1!"false"]>
    <#assign isCellIntTable += ["true"]>
    <#assign Cell1PortPriority = 100+p>
  </#if>
</#list>

<#if priorityIfNameTable?size <=0>
  <#-- No interface in the priority table
       This scenario should never happen -->
   ${provisioningFailed("Need at least one WAN interface enabled on ${far.eid}")}
<#else>
  <#-- Iterate over interface table list, by configured priority from 1 to 4 -->
  <#list 0 .. (priorityIfNameTable?size-1) as p>
    !
    ! ***** ${priorityIfNameTable[p]} configuration *****
    !
    <#-- Config for Cell interface are slightly different -->
    <#if isCellIntTable[p] == "true">
      track ${p+10} interface ${priorityIfNameTable[p]} line-protocol
      ip route 0.0.0.0 0.0.0.0 ${priorityIfNameTable[p]} ${100+p} track ${p+40}
      ip route ${ipslaDestIPaddress[p]} 255.255.255.255 ${priorityIfNameTable[p]} track ${p+10}
    <#else>
      ip route 0.0.0.0 0.0.0.0 ${priorityIfNameTable[p]} dhcp ${100+p}
      ip route ${ipslaDestIPaddress[p]} 255.255.255.255 dhcp
    </#if>
    ip route ${ipslaDestIPaddress[p]} 255.255.255.255 Null0 3
    ip sla ${p+40}
      icmp-echo ${ipslaDestIPaddress[p]} source-interface ${priorityIfNameTable[p]}
      frequency <#if isCellIntTable[p] == "true">50<#else>10</#if>
    !
    !
    ip sla schedule ${p+40} life forever start-time now
      track ${p+40} ip sla ${p+40} reachability
    event manager applet failover_${p+40}
      event track ${p+40} state any
      action 0.1 syslog msg "${priorityIfNameTable[p]} connectivity change, clearing NAT translations"
      action 0.2 cli command "enable"
      action 1.0 cli command "clear ip nat translation *"
    <#if isCellIntTable[p] != "true">
      <#-- this is not cellular, use DHCP -->
      int ${priorityIfNameTable[p]}
        <#-- ip dhcp client route track ${p+40} -->
      <#-- This will enable the client route track via EEM, since config causes Registration failure-->
      <#assign eventAppName = priorityIfNameTable[p]?replace(" ", "_")>
      event manager applet client_route_track_${eventAppName}
        event timer watchdog time 60
        action 1 cli command "en"
        action 2 cli command "show cgna profile name cg-nms-register | i disabled"
        action 3 string match "*Profile disabled*" "$_cli_result"
        action 4 if $_string_result eq "0"
        action 5  exit
        action 6 end
        action 7.0 cli command "conf t"
        action 7.1 cli command "interface ${priorityIfNameTable[p]}"
        action 7.2 cli command "ip address dhcp"
        action 7.3 cli command "exit"
        action 8.0 cli command "no event manager applet client_route_track_${eventAppName}"
        action 8.1 cli command "exit"
        action 9.0 cli command "write mem"
    </#if>
    int ${priorityIfNameTable[p]}
    zone-member security INTERNET
    ip nat outside
    no shutdown
    <#if isTunnelEnabledTable[p] == "true" && isPrimaryHeadEndEnable == "true">
      crypto ikev2 client flexvpn ${vpnTunnelIntf}
      source ${p+1} ${priorityIfNameTable[p]} track ${p+40}
      <#if isCellIntTable[p] != "true">
        <#assign suffix = "dhcp">
      <#else>
        <#assign suffix = " ">
      </#if>
      <#if herIpAddress?has_content && isPrimaryHeadEndEnable == "true">
        ip route ${herIpAddress} 255.255.255.255 ${priorityIfNameTable[p]} ${suffix}
        <#if backupHerIpAddress?has_content && isSecondaryHeadEndEnable == "true">
          ip route ${backupHerIpAddress} 255.255.255.255 ${priorityIfNameTable[p]} ${suffix}
        </#if>
      </#if>
    </#if>
  </#list>
</#if>

!

!
ip ssh rsa keypair-name SSHKEY
ip ssh version 2
ip scp server enable
!
ip access-list extended filter-internet
 permit icmp any any echo
 permit icmp any any echo-reply
 permit icmp any any unreachable
 permit icmp any any packet-too-big
 permit icmp any any ttl-exceeded
 permit udp any eq bootps host 255.255.255.255 eq bootpc
<#if primaryHerIpAddress?has_content>
 permit esp host ${herIpAddress} any
</#if>
<#if backupHerIpAddress?has_content>
  permit esp host ${backupHerIpAddress} any
</#if>
!

<#-- Enable NAT and routing -->
<#assign gwips = far.lanIPAddress?split(".")>
<#assign nwk_suffix = (gwips[3]?number / 32)?int * 32>
<#assign nwk_addr = gwips[0] + "." + gwips[1] + "." + gwips[2] + "." + (nwk_suffix + 5)>
ip access-list extended NAT_ACL
     permit ip ${lanNtwk} ${lanWild} any
     permit ip ${nwk_addr} 0.0.0.31 any

!
<#if isPrimaryHeadEndEnable == "true">
route-map RM_Tu2 permit 10
     match ip address NAT_ACL
     match interface ${vpnTunnelIntf}
</#if>
!
dialer-list 1 protocol ip permit
!
!
<#if isFirstCell == "true">
route-map RM_WAN_ACL permit 10
    match ip address NAT_ACL
    match interface ${cell_if1}
!
</#if>
route-map RM_WAN_ACL2 permit 10
    match ip address NAT_ACL
    match interface ${ether_if}
!
<#if isFirstCell == "true">
ip nat inside source route-map RM_WAN_ACL interface ${cell_if1} overload
</#if>
ip nat inside source route-map RM_WAN_ACL2 interface ${ether_if} overload
line vty 0 4
    exec-timeout 5 0
    length 0
    transport input ssh
!

<#-- Set APN -->

<#if APN?has_content>
event manager applet change_apn
event timer countdown time 10
action 5 syslog msg "Changing APN Profile"
action 10 cli command "enable"
action 15 cli command "${cell_if1} lte profile create 1 ${APN}" pattern "confirm"
action 20 cli command "y"
!
!
</#if>

<#-- generare RSA keys for SSH -->

event manager applet ssh_crypto_key authorization bypass
  event timer cron cron-entry "@reboot" maxrun 60
  action 1.0 cli command "enable"
  action 2.0 cli command "show ip ssh | include ^SSH"
  action 2.1 regexp "([ED][^ ]+)" "$_cli_result" _result
  action 3.0 if $_result eq Disabled
  action 3.1   syslog msg "EEM:ssh_crypto_key generating new SSHKEY "
  action 3.2   cli command "config t"
  action 3.3   cli command "crypto key generate rsa usage-keys label SSHKEY modulus 2048"
  action 3.4   cli command "end"
  action 3.5   cli command "write mem" pattern "confirm|#"
  action 3.6   regexp "confirm" "$_cli_result"
  action 3.7   if $_regexp_result eq "1"
  action 3.8     cli command "y"
  action 3.9   end
  action 4.0 end
  action 5.1 syslog msg "EEM:ssh_crypto_key hara-kiri "
  action 5.2 cli command "config t"
  action 5.3 cli command "no event manager applet ssh_crypto_key"


<#-- End eCVD template -->

<#elseif far.isRunningCgOs()>

<#else>
  ${provisioningFailed("FAR is not running CG-OS or IOS")}
</#if>
