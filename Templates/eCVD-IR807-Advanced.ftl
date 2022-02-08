<#-- ---- Begin eCVD template for IR807 -----
  ---- Version 1.89 -----------------------
  -----------------------------------------
  -- This template for IR807 was NOT     --
  -- validated by the CVD team and is    --
  -- only provided as a courtesy    --
-->

<#compress>

<#-- Set dumpAllVariables to true to dump all template variables
     in the config for debugging. This will also dump all passwords in
     clear text. -->
<#assign dumpAllVariables = false>

<#-- extract PID and SN from EID - ie. IR829-K9+FCW23510HKN -->
<#assign sublist 		= "${far.eid}"?split("+")[0..1]>
<#assign pid = sublist[0]>
<#assign model = pid[0..4]>
<#assign sn = sublist[1]>

<#if ! pid?starts_with("IR807")>
  ${provisioningFailed("This template is for IR807 and does not support ${pid}")}
</#if>

<#-- PLATFORM SPECIFIC VARIABLES -->
<#assign ether_if = "FastEthernet0">
<#assign cell_if1 = "Cellular 0">
<#assign cell_if1_contr = "Cellular 0">
<#assign isGpsEnabled = "true">
<#assign vpnTunnelIntf = "Tunnel2">

<#-- TEMPLATE CONSTANTS -->
<#assign umbrella_dns1_ip = "208.67.222.222">
<#assign umbrella_dns2_ip = "208.67.220.220">

<#-- VARIABLES INITIALIZATION -->
<#assign highestPriorityIfName = 1>
<#assign priorityIfNameTable = []>
<#assign isTunnelEnabledTable = []>
<#assign isCellIntTable = []>
<#assign EthernetPortPriority = 200>
<#assign Cell1PortPriority = 200>

<#-- IP SLA destination IP addresses -->

<#assign ipslaDestIPaddress = [far.IcmpReachableIPaddress1!"4.2.2.1",
    far.IcmpReachableIPaddress2!"4.2.2.2",
    far.IcmpReachableIPaddress3!"9.9.9.10",
    far.IcmpReachableIPaddress4!"9.9.9.11"]>

<#-- Interface Menu -->
<#assign fastEthernet1_enabled = far.fastEthernet1!"true">

<#-- Allows the template to prompt for "admin" password.
     IoTOC will generate one by default during claim but
     can be changed here -->
<#-- may cause issues if not net, password NULL -->
<#-- assign adminPassword = far..adminPassword --->

<#-- WAN Menu -->

<#if section.wan_ethernet?has_content && section.wan_ethernet == "true">
  <#assign isEthernetEnable = "true">
  <#assign ethernetPriority = far.ethernetPriority>
<#else>
  <#assign isEthernetEnable = "false">
</#if>

<#assign isFirstCell = "false">
<#assign isGpsEnabled = "true">
<#if section.wan_cellular1?has_content && section.wan_cellular1 == "true">
  <#assign isFirstCell = "true">
  <#if far.apn1?has_content && far.apn1 != "null">
    <#assign APN1			= far.apn1>
  </#if>
</#if>

<#-- LAN Menu -->
<#assign lanIP 		= "${far.lanIPAddress}"?split(".")>
<#assign lanNet 	= "${far.lanNetmask}"?split(".")>

<#-- Network Menu -->

<#-- Security Menu -->

<#-- Umbrella not supported on IR829 -->
<#assign isUmbrella = "false">

<#assign isNetFlow = "false">
<#if section.security_netflow?has_content && section.security_netflow == "true">
  <#assign isNetFlow = "true">
  <#if far.netflowCollectorIP?has_content>
    <#assign netflowCollectorIP = far.netflowCollectorIP>
  </#if>
</#if>

<#-- VPN Settings Menu -->
<#assign isPrimaryHeadEndEnable = "false">
<#assign isSecondaryHeadEndEnable = "false">
<#if section.vpn_primaryheadend?has_content && section.vpn_primaryheadend == "true">
  <#if far.herIpAddress?has_content && far.herPsk?has_content>
    <#assign herIpAddress 	= "${far.herIpAddress}">
    <#assign herPsk			    = "${far.herPsk}">
    <#assign isPrimaryHeadEndEnable = "true">
  </#if>
  <#if section.vpn_backupheadend?has_content && section.vpn_backupheadend == "true">
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

<#-- If no DNS specified, assign Umbrella DNS servers -->
<#assign umbrella_dns1_ip = "208.67.222.222">
<#assign umbrella_dns2_ip = "208.67.220.220">
<#assign dns1 = far.lanDNSIPAddress1!umbrella_dns1_ip>
<#assign dns2 = far.lanDNSIPAddress2!umbrella_dns2_ip>
<#assign DNSIP		= "${dns1} ${dns2}">

<#-- Setting up time zone settings -->
<#if far.clockTZ?has_content>
  <#assign clockTZ = far.clockTZ>
<#else>
  <#assign clockTZ = "gmt">
</#if>

<#if far.ntpIP?has_content>
  <#assign ntpIP = far.ntpIP>
<#else>
  <#assign ntpIP = "time.nist.gov">
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

<#assign TZ = { "anat":"+12", "sbt":"+11", "aest":"+10", "jst":"+9", "cst":"+8", "wib":"+7", "btt":"+6", "uzt":"+5", "gst":"+4", "msk":"+3", "cest":"+2", "bst":"+1", "gmt":"0", "cvt":"-1", "wgst":"-2", "art":"-3", "edt":"-4", "cdt":"-5", "mst":"-6", "pdt":"-7", "akdt":"-8", "hdt":"-9", "hst":"-10", "nut":"-11", "aeo":"-12" }>
<#assign offset = 0>
<#list TZ as x, y >
	<#if x == clockTZ>
		<#assign offset = y>
		<#break>
	</#if>
</#list>

<#if section.network_qos?has_content && section.network_qos == "true">
  <#assign isQosEnabled = "true">
  <#if far.qosBandwidth?has_content>
    <#assign qosBandwidth = far.qosBandwidth>
  </#if>
  <#if far.qos?has_content>
    <#assign qosPolicyTable = far.qos>
  </#if>
<#else>
  <#assign isQosEnabled = "false">
</#if>

<#-- Configure Device Settings -->

service tcp-keepalives-in
service tcp-keepalives-out
service timestamps debug datetime msec
service timestamps log datetime msec
service password-encryption
no service config
no service call-home
!
clock timezone ${clockTZ} ${offset}
ntp server ${ntpIP}
!
ip domain name ${domainName}
!
ip dhcp pool subtended
    network ${lanNtwk} ${far.lanNetmask}
    default-router ${far.lanIPAddress}
    dns-server ${DNSIP}
    lease 0 0 10
!
<#if far.lanIPAddressDHCPexcludeRangeStart?has_content && far.lanIPAddressDHCPexcludeRangeEnd?has_content>
  ip dhcp excluded-address ${far.lanIPAddressDHCPexcludeRangeStart} ${far.lanIPAddressDHCPexcludeRangeEnd}
</#if>
!
<#-- create users as defined in the template -->
<#if far.Users?has_content>
  <#list far.Users as user >
    <#if user['userName']?has_content &&
          user['userPassword']?has_content &&
          user['userPriv']?has_content>
		  <#if user['userName'] == "admin">
		    <#-- "admin" user is already used by IoT OC, ignore -->
		    <#continue>
		  </#if>
      <#-- here we made sure to have username, password and pivillege defined -->
		  username ${user['userName']} privilege ${user['userPriv']} algorithm-type scrypt secret ${user['userPassword']}
    </#if>
  </#list>
</#if>
!
<#-- S2S VPN Configuration -->
!
<#if isPrimaryHeadEndEnable == "true" && herIpAddress?has_content && herPsk?has_content>
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
    <#if isSecondaryHeadEndEnable == "true">
		  <#if backupHerIpAddress?has_content && backupHerPsk?has_content>
        peer ${backupHerIpAddress}
        address ${backupHerIpAddress}
        identity key-id ${backupHerIpAddress}
        pre-shared-key ${backupHerPsk}
      </#if>
		</#if>
!
  crypto ikev2 profile CVPN_I2PF
    match identity remote key-id ${herIpAddress}
    <#if isSecondaryHeadEndEnable == "true">
      <#if backupHerIpAddress?has_content>
        match identity remote key-id ${backupHerIpAddress}
	    </#if>
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
interface ${vpnTunnelIntf}
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
crypto ikev2 client flexvpn ${vpnTunnelIntf}
  peer 1 ${herIpAddress}
  <#if isSecondaryHeadEndEnable == "true">
    peer 2 ${backupHerIpAddress}
  </#if>
  client connect ${vpnTunnelIntf}
!
</#if>

<#-- interface priorities -->

<#list 1..4 as p>
  <#if isEthernetEnable == "true"
        && ether_if?? && ethernetPriority?has_content
        && ethernetPriority == p?string>
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
      <#-- Cell interface do not require the source for the SLA -->
      <#if isCellIntTable[p] == "true">
      	icmp-echo ${ipslaDestIPaddress[p]}
        frequency 50
      <#else>
        icmp-echo ${ipslaDestIPaddress[p]} source-interface ${priorityIfNameTable[p]}
        frequency 10
      </#if>
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
        ip route ${herIpAddress} 255.255.255.255 ${priorityIfNameTable[p]} ${suffix} ${p+40}
        <#if backupHerIpAddress?has_content && isSecondaryHeadEndEnable == "true">
          ip route ${backupHerIpAddress} 255.255.255.255 ${priorityIfNameTable[p]} ${suffix} ${p+40}
        </#if>
      </#if>
    </#if>
  </#list>
</#if>

<#-- Zone based firewall.  Expands on Bootstrap config -->

ip access-list extended eCVD-deny-from-outside

<#assign count = 10>
<#if far.firewallIp??>
<#list far.firewallIp as FW>
  <#if FW['fwType']?has_content>
   <#if FW['fwType'] == "deny">
    <#if FW['fwProtocol'] == "ip" || FW['fwProtocol'] == "icmp">
   ${count} deny ${FW['fwProtocol']} ${FW['fwSrcIp']} ${FW['fwSrcMask']} any
    <#else>
   ${count} deny ${FW['fwProtocol']} ${FW['fwSrcIp']} ${FW['fwSrcMask']} eq ${FW['fwPort']} any
    </#if>
   <#assign count += 10>
   </#if>
  </#if>
 </#list>
</#if>

  ip access-list extended eCVD-permit-from-outside

<#assign count = 10>
<#if far.firewallIp??>
<#list far.firewallIp as FW>
  <#if FW['fwType']?has_content>
   <#if FW['fwType'] == "allow">
    <#if FW['fwProtocol'] == "ip" || FW['fwProtocol'] == "icmp">
   ${count} permit ${FW['fwProtocol']} ${FW['fwSrcIp']} ${FW['fwSrcMask']} any
    <#else>
   ${count} permit ${FW['fwProtocol']} ${FW['fwSrcIp']} ${FW['fwSrcMask']} eq ${FW['fwPort']} any
    </#if>
   <#assign count += 10>
   </#if>
  </#if>
 </#list>
</#if>
!
 class-map type inspect match-any eCVD-deny-list
   match access-group name eCVD-deny-from-outside
!
 class-map type inspect match-any eCVD-permit-list
   match access-group name eCVD-permit-from-outside
!
!
  policy-map type inspect INTERNET2Any
    class type inspect eCVD-permit-list
      inspect
    class type inspect eCVD-deny-list
      drop
!
int ${ether_if}
  zone-member security INTERNET
  !
<#if isFirstCell == "true">
int ${cell_if1}
  zone-member security INTERNET
  !
</#if>
!
<#-- QoS config for IOS Classic -->
<#if isQosEnabled == "true">
  <#if qosBandwidth?has_content>
    <#assign QOSbw = qosBandwidth?number>

    <#if qosPolicyTable?has_content>
      class-map match-any CLASS-GOLD
      <#-- traffic class possible values are listed below.  User should be able to place multiple TCs in a class (gold, silver, bronze). -->
      <#list qosPolicyTable as QOS>
        <#if QOS['qosType']?has_content>
          <#if QOS['qosPriority'] == "hi">
            match protocol attribute traffic-class ${QOS['qosType']}
          </#if>
        </#if>
      </#list>
!
      class-map match-any CLASS-SILVER
      <#list qosPolicyTable as QOS>
        <#if QOS['qosType']?has_content>
          <#if QOS['qosPriority'] == "med">
            match protocol attribute traffic-class ${QOS['qosType']}
          </#if>
        </#if>
      </#list>
!
      class-map match-any CLASS-BRONZE
      <#list qosPolicyTable as QOS>
        <#if QOS['qosType']?has_content>
          <#if QOS['qosPriority'] == "low">
            match protocol attribute traffic-class ${QOS['qosType']}
          </#if>
        </#if>
      </#list>
!
      class-map match-any CLASS-SILVER-BRONZE
      <#list qosPolicyTable as QOS>
        <#if QOS['qosType']?has_content>
          <#if QOS['qosPriority'] == "med" || QOS['qosPriority'] == "low">
            match protocol attribute traffic-class ${QOS['qosType']}
          </#if>
        </#if>
      </#list>
!
      policy-map SUB-CLASS-SILVER-BRONZE
       class CLASS-SILVER
       <#-- calculate based on 20% of upstream bandwidth, in kbps -->
       <#assign qosbwkb = QOSbw * 0.20>
       bandwidth ${qosbwkb?int?c}
       class CLASS-BRONZE
        <#-- calculate based on 25% of upstream bandwidth, in kbps -->
        <#assign qosbwkb = QOSbw * 0.25>
        bandwidth ${qosbwkb?int?c}
!
      policy-map SUB-CLASS-GSB
      class CLASS-GOLD
        <#-- kbps.  10% of user entered upstream bandwidth -->
        <#assign qosbwkb = QOSbw * 0.10>
         priority ${qosbwkb?int?c}
      class CLASS-SILVER-BRONZE
       <#-- calculate based on 60% of total upstream in bps -->
       <#assign qbw = QOSbw * 0.60 * 1000>
       shape average ${qbw?int?c}
       <#assign qosbwkb = QOSbw * 0.60>
       bandwidth ${qosbwkb?int?c}
       service-policy SUB-CLASS-SILVER-BRONZE
      class class-default
       fair-queue
       random-detect dscp-based
!
      policy-map CELL_WAN_QOS
       class class-default
        <#assign qbw = QOSbw * 1000>
        shape average ${qbw?int?c}
        service-policy SUB-CLASS-GSB

      <#if isFirstCell?has_content && isFirstCell == "true">
        interface ${cell_if1}
          service-policy output CELL_WAN_QOS
      </#if>
    </#if>
  </#if>
</#if>

<#-- --- END OF QoS CONFIG ----------------------------- -->

<#-- Enable GPS  -->
<#if isGpsEnabled?has_content && isGpsEnabled == "true">
controller ${cell_if1_contr}
  lte gps mode standalone
</#if>
!
<#if isFirstCell == "true">
interface ${cell_if1}
    ip address negotiated
    dialer in-band
    encapsulation slip
    dialer idle-timeout 0
    dialer-group 1
    dialer string lte
</#if>
!
<#if fastEthernet1_enabled == "true">
interface FastEthernet1
    description SUBTENDED NETWORK
    ip address ${far.lanIPAddress} ${far.lanNetmask}
    ip nat inside
    ip verify unicast source reachable-via rx
    no shutdown
</#if>
!
!
interface Async0
    no ip address
    encapsulation scada
!
<#-- Enable NAT and routing -->
ip access-list extended NAT_ACL
  ! subtended
  permit ip ${lanNtwk} ${lanWild} any
  ! IOx pool
  permit ip 10.9.51.0 0.0.0.255 any
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
ip forward-protocol nd
!
<#if isFirstCell == "true">
ip nat inside source route-map RM_WAN_ACL interface ${cell_if1} overload
</#if>
ip nat inside source route-map RM_WAN_ACL2 interface ${ether_if} overload

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

no ip route 0.0.0.0 0.0.0.0 ${cell_if1} 100

<#if isPrimaryHeadEndEnable == "true" && herIpAddress?has_content>
  ip route ${herIpAddress}  255.255.255.255 ${ether_if} dhcp
  <#if isSecondaryHeadEndEnable == "true" && backupHerIpAddress?has_content>
    ip route ${backupHerIpAddress} 255.255.255.255 ${ether_if} dhcp
  </#if>
</#if>
!
<#-- User defined static routes with either next hop or egress interface -->
<#if far.staticRoute?has_content>
  <#list far.staticRoute as SR>
    <#if SR['destNetwork']?has_content>
      <#assign dst_intf = "">
      <#switch SR['nextInterface']>
        <#case "ether_if">
          <#assign dst_intf = ether_if!"">
          <#break>
        <#case "cell_if1">
          <#assign dst_intf = cell_if1!"">
          <#break>
        <#case "VPN">
          <#assign dst_intf = vpnTunnelIntf!"">
          <#break>
      </#switch>
      <#if dst_intf?has_content>
        ip route ${SR['destNetwork']} ${SR['destNetMask']} ${dst_intf}
      </#if>
    </#if>
  </#list>
</#if>
!
<#if isPrimaryHeadEndEnable == "true">
ip nat inside source route-map RM_Tu2 interface ${vpnTunnelIntf} overload
</#if>
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
<#if isPrimaryHeadEndEnable == "true" && herIpAddress?has_content>
 permit esp host ${herIpAddress} any
  <#if isSecondaryHeadEndEnable == "true" && backupHerIpAddress?has_content>
    permit esp host ${backupHerIpAddress} any
  </#if>
</#if>
!

<#-- ADDED 11 LINES BELOW FOR ADVANCED -->
<#-- OPTIONALLY remove NAT overload config and config and setup routing over FlexVPN S2SVPN -->
<#if isPrimaryHeadEndEnable == "true">
no ip nat inside source route-map RM_Tu2 interface ${vpnTunnelIntf} overload
no route-map RM_Tu2 permit 10

interface ${vpnTunnelIntf}
 no ip nat outside
!
</#if>

ip access-list standard CLOUD
  permit ${lanNtwk} ${lanWild}

<#if isPrimaryHeadEndEnable == "true">
crypto ikev2 authorization policy CVPN
  route set access-list CLOUD
!
</#if>

<#-- ADDED LINES BELOW FOR ADVANCED -->
<#-- Reverse telnet to serial port at TCP port 2050 -->
!
line console 0
  transport output telnet ssh
  databits 8
  parity none
  stopbits 1
  speed 9600

line vty 0 4
    exec-timeout 5 0
    length 0
    transport input ssh

<#-- ADDED LINES BELOW FOR ADVANCED -->
<#-- Netflow -->

<#if isNetflow?has_content && isNetflow == "true" && netflowCollectorIP?has_content>
 flow record defaultStealthWatch
  match ipv4 protocol
  match ipv4 source address
  match ipv4 destination address
  match transport source-port
  match transport destination-port
  match interface input
  match ipv4 tos
  collect interface output
  collect counter bytes long
  collect counter packets
  collect timestamp sys-uptime first
  collect timestamp sys-uptime last

flow exporter export_Gi0_0_0_-63055531
 destination ${netflowCollectorIP}
 source Loopback 1
 transport udp 2055
 template data timeout 60

flow monitor dsw_Gi0_0_0_-63055531
 exporter export_Gi0_0_0_-63055531
 cache timeout active 60
 record defaultStealthWatch
<#-- add logic to use other WAN interfaces -->
interface ${ether_if}
 ip flow monitor dsw_Gi0_0_0_-63055531 input
!
!
</#if>

<#-- ------------------------------------------ -->
<#-- ------------------------------------------ -->
<#-- ------------------------------------------ -->

<#-- generare RSA keys for SSH -->

event manager applet ssh_crypto_key authorization bypass
  event timer watchdog time 5 maxrun 60
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


<#-- Set APN -->

<#if isFirstCell?has_content && isFirstCell == "true" && APN1?has_content>
  event manager applet change_apn_cell1
  event timer countdown time 10
  action 5 syslog msg "Changing APN Profile"
  action 10 cli command "enable"
  action 15 cli command "${cell_if1} lte profile create 1 ${APN1}" pattern "confirm"
  action 20 cli command "y"
</#if>

<#-- -- LOGGING ONLY ------------------------- -->
<#if dumpAllVariables>
  <#assign dumpSubParams = ['far', 'section', 'nms']>
    <#list dumpSubParams as subParm>
    event manager applet ListAll_${subParm}
    <#assign i = 100>
    <#list subParm?eval as key, value>
      <#if value??>
        <#if value?is_string>
          action ${i} cli command "${subParm}.${key} = ${value}"
          <#assign i = i + 1>
        <#elseif value?is_sequence>
          <#assign subi = 0>
          <#list value as val>
            <#list val as subkey, subvalue>
              action ${i} cli command "${subParm}.${key} [${subi}] ${subkey} = ${subvalue}"
              <#assign i = i + 1>
            </#list>
            <#assign subi = subi + 1>
          </#list>
        </#if>
      <#elseif !value??>
        action ${i} cli command "${subParm}.${key} = *null*"
        <#assign i = i + 1>
      </#if>
    </#list>
  </#list>
</#if> <#-- end of dumpAllVariables -->
<#-- END OF LOGGING ONLY --------------------- -->

</#compress>

<#-- End eCVD template -->
