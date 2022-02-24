<#--
     ---- Begin eCVD template for IR1101 -----
     ---- Version 2.0 -----------------------
     -----------------------------------------
     -- Support single and dual Radio       --
     -- Site to Site VPN                    --
     -- QoS, Port Forwarding, Static Route  --
     -- Umbrella with pattern bypass        --
-->

<#compress>

<#-- Set dumpAllVariables to true to dump all template variables
     in the config for debugging. This will also dump all passwords in
     clear text. -->
<#assign dumpAllVariables = false>

<#-- extract PID and SN from EID - ie. IR1101-K9+FCW23510HKN -->
<#assign sublist 		= "${far.eid}"?split("+")[0..1]>
<#assign pid = sublist[0]>
<#assign model = pid[0..5]>
<#assign sn = sublist[1]>

<#if pid != "IR1101-K9" && pid != "IR1101-A-K9">
  ${provisioningFailed("This template is for IR1101 and does not support ${pid}")}
</#if>


<#-- Device Settings Menu -->
<#if far.localDomainName?has_content>
  <#assign domainName = "${far.localDomainName}">
<#else>
  <#assign domainName = "local">
</#if>

<#-- Allows the template to prompt for "admin" password.
     IoTOC will generate one by default during claim but
     can be changed here -->
<#-- may cause issues if not net, password NULL -->
<#-- assign adminPassword = far..adminPassword --->
<#-- USER MANAGEMENT SECTION -->
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


<#-- PLATFORM SPECIFIC VARIABLES -->
<#assign ether_if = "GigabitEthernet 0/0/0">
<#assign cell_if1 = "Cellular 0/1/0">
<#assign cell_if2 = "Cellular 0/3/0">
<#assign vpnTunnelIntf = "Tunnel2">
<#assign isWgbEnable = "false">

<#-- TEMPLATE CONSTANTS -->
<#assign umbrella_dns1_ip = "208.67.222.222">
<#assign umbrella_dns2_ip = "208.67.220.220">

<#-- VARIABLES INITIALIZATION -->
<#assign highestPriorityIfName = 1>
<#assign priorityIfNameTable = []>
<#assign isTunnelEnabledTable = []>
<#assign isCellIntTable = []>
<#assign EthernetPortPriority = 200>
<#assign WgbIntPriority = 200>
<#assign Cell2PortPriority = 200>
<#assign Cell1PortPriority = 200>


<#-- WAN Menu -->

<#assign ipslaDestIPaddress = []>

<#assign isEthernetEnable = "false">
<#assign isFirstCell = "false">
<#assign isSecondCell = "false">

<#assign interfaces_list=[]>
<#assign wan_descriptions = []>
<#assign wan_eth_description = "">
<#assign wan_cell1_description = "">
<#assign wan_cell2_description = "">


<#assign wan_link1_interface = far.wanUplink1Interface>
<#assign interfaces_list += [wan_link1_interface]>
<#if far.wanUplink1Description?has_content && far.wanUplink1Description != "null">
  <#assign wan_descriptions += [far.wanUplink1Description]>
<#else>
  <#assign wan_descriptions += [""]>
</#if>
<#assign wan_link1_sla = far.wanUplink1SLA>
<#if wan_link1_interface == "cellular1" && far.wan1APN?has_content && far.wan1APN != "null">
  <#assign APN1 = far.wan1APN>
<#elseif wan_link1_interface == "cellular2" && far.wan1APN?has_content && far.wan1APN != "null">
  <#assign APN2 = far.wan1APN>
</#if>

<#if section.wan_wanuplink2?has_content && section.wan_wanuplink2 == "true">
  <#assign wan_link2_interface = far.wanUplink2Interface>
  <#assign interfaces_list += [wan_link2_interface]>
  <#if far.wanUplink2Description?has_content && far.wanUplink2Description != "null">
    <#assign wan_descriptions += [far.wanUplink2Description]>
  <#else>
    <#assign wan_descriptions += [""]>
  </#if>
  <#assign wan_link2_sla = far.wanUplink2SLA>
  <#if wan_link2_interface == "cellular1" && far.wan2APN?has_content && far.wan2APN != "null">
    <#assign APN1 = far.wan2APN>
  <#elseif wan_link2_interface == "cellular2" && far.wan2APN?has_content && far.wan2APN != "null">
    <#assign APN2 = far.wan2APN>
  </#if>
</#if>

<#if section.wan_wanuplink3?has_content && section.wan_wanuplink3 == "true">
  <#assign wan_link3_interface = far.wanUplink3Interface>
  <#assign interfaces_list += [wan_link3_interface]>
  <#if far.wanUplink3Description?has_content && far.wanUplink3Description != "null">
    <#assign wan_descriptions += [far.wanUplink3Description]>
  <#else>
    <#assign wan_descriptions += [""]>
  </#if>
  <#assign wan_link3_sla = far.wanUplink3SLA>
  <#if wan_link3_interface == "cellular1" && far.wan3APN?has_content && far.wan3APN != "null">
    <#assign APN1 = far.wan3APN>
  <#elseif wan_link3_interface == "cellular2" && far.wan3APN?has_content && far.wan3APN != "null">
    <#assign APN2 = far.wan3APN>
  </#if>
</#if>


<#-- IP SLA destination IP addresses -->

<#assign ipslaDestIPaddress = [far.wanUplink2SLA!"4.2.2.1",
    far.wanUplink2SLA!"4.2.2.2",
    far.wanUplink3SLA!"9.9.9.10"]>

<#-- by default GPS is off -->
<#assign isGpsEnabled = "false">
<#if far.cellFirmwareVersion1?has_content && far.cellFirmwareVersion1?starts_with("SWI")>
  <#-- taking wild guess that if Sierra Wireless firmware it
     probably has GPS capability. -->
  <#assign isGpsEnabled = "true">
</#if>



<#-- DHCP Menu -->
<#assign lanIP 		= "${far.dhcpIPAddress}"?split(".")>
<#assign lanNet 	= "${far.dhcpNetmask}"?split(".")>
<#-- DHCP Range Exclusion start = far.dhcpExcludeRangeStart -->
<#-- DHCP Range Exclusion end = far.dhcpExcludeRangeEnd -->
<#if far.dhcpHelperIP?has_content && far.dhcpHelperIP != "null">
  <#assign helper_address = far.dhcpHelperIP>
</#if>

<#-- DNS/NTP Section -->
<#-- If no DNS specified, assign Umbrella DNS servers -->

<#assign umbrella_dns1_ip = "208.67.222.222">
<#assign umbrella_dns2_ip = "208.67.220.220">
<#assign dns1 = far.dnsIPAddress1!umbrella_dns1_ip>
<#assign dns2 = far.dnsIPAddress2!umbrella_dns2_ip>
<#assign DNSIP		= "${dns1} ${dns2}">

<#if far.ntpPrimaryIP?has_content>
  <#assign ntpIP = far.ntpPrimaryIP>
  <#if far.ntpSecondaryIP?has_content>
    <#assign ntpIP2 = far.ntpSecondaryIP>
  </#if>
<#else>
  <#assign ntpIP = "time.nist.gov">
</#if>

<#-- Setting up time zone settings -->
<#if far.clockTZ?has_content>
  <#assign clockTZ = far.clockTZ>
<#else>
  <#assign clockTZ = "gmt">
</#if>

<#-- Interface Menu - which Ethernet interfaces are enabled? -->
<#assign FastEthernet1_enabled = far.intFastEthernet1!"true">
<#assign FastEthernet2_enabled = far.intFastEthernet2!"true">
<#assign FastEthernet3_enabled = far.intFastEthernet3!"true">
<#assign FastEthernet4_enabled = far.intFastEthernet4!"true">

<#assign fastEth1Des = "SUBTENDED">
<#assign fastEth2Des = "SUBTENDED">
<#assign fastEth3Des = "SUBTENDED">
<#assign fastEth4Des = "SUBTENDED">

<#if far.fastEthernet1Description?has_content && far.fastEthernet1Description != "null">
  <#assign fastEth1Des = far.fastEthernet1Description!"true">
</#if>
<#if far.fastEthernet2Description?has_content && far.fastEthernet2Description != "null">
  <#assign fastEth2Des = far.fastEthernet2Description!"true">
</#if>
<#if far.fastEthernet3Description?has_content && far.fastEthernet3Description != "null">
  <#assign fastEth3Des = far.fastEthernet1Description!"true">
</#if>
<#if far.fastEthernet4Description?has_content && far.fastEthernet4Description != "null">
  <#assign fastEth4Des = far.fastEthernet1Description!"true">
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


<#-- NETWORK Menu -->

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


<#-- Security Menu -->
<#assign isNetflow = "false">
<#if section.security_netflow?has_content && section.security_netflow == "true">
  <#assign isNetflow = "true">
  <#if far.netflowCollectorIP?has_content>
    <#assign netflowCollectorIP = far.netflowCollectorIP>
  </#if>
</#if>

<#assign isUmbrella = "false">
<#if section.security_umbrella?has_content && section.security_umbrella == "true" && far.umbrellaToken?has_content>
  <#assign isUmbrella = "true">
  <#assign UmbrellaToken = "${far.umbrellaToken}">
</#if>


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
<#-- #TODO We may need to disable logging console later in production -->
<#-- no logging console -->
!



clock timezone ${clockTZ} ${offset}
ntp server ${ntpIP}
!
ip domain name ${domainName}
!
ip dhcp pool subtended
    network ${lanNtwk} ${far.dhcpNetmask}
    default-router ${far.dhcpIPAddress}
    dns-server ${DNSIP}
    lease 0 0 10
!
<#if far.dhcpExcludeRangeStart?has_content && far.dhcpExcludeRangeEnd?has_content>
  ip dhcp excluded-address ${far.dhcpExcludeRangeStart} ${far.dhcpExcludeRangeEnd}
</#if>
!
!
<#-- S2S VPN Configuration -->
!
<#if isPrimaryHeadEndEnable == "true">
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

<#assign used_int = []>

<#list 0 .. (interfaces_list?size-1) as x>
  <#if interfaces_list[x] == "ethernet" && !used_int?seq_contains(interfaces_list[x])>
   <#assign used_int += [interfaces_list[x]]>
   <#if wan_descriptions[x] != "">
    <#assign wan_eth_description = wan_descriptions[x]>
   </#if>
   <#assign isEthernetEnable = "true">
   <#assign ethernetPriority = x + 1>
   <#assign priorityIfNameTable += [ether_if]>
   <#assign isTunnelEnabledTable += [far.enableTunnelOverEthernet!"false"]>
   <#assign isCellIntTable += ["false"]>
   <#assign EthernetPortPriority = 100+x>
  </#if>

  <#if interfaces_list[x] == "cellular1" && !used_int?seq_contains(interfaces_list[x])>
   <#assign used_int += [interfaces_list[x]]>
   <#if wan_descriptions[x] != "">
    <#assign wan_cell1_description = wan_descriptions[x]>
   </#if>
   <#assign isFirstCell = "true">
   <#assign firstCellPriority = x + 1>
   <#assign priorityIfNameTable += [cell_if1]>
   <#assign isTunnelEnabledTable += [far.enableTunnelOverCell1!"false"]>
   <#assign isCellIntTable += ["true"]>
   <#assign Cell1PortPriority = 100+x>
  </#if>

  <#if interfaces_list[x] == "cellular2" && !used_int?seq_contains(interfaces_list[x])>
   <#assign used_int += [interfaces_list[x]]>
   <#if wan_descriptions[x] != "">
    <#assign wan_cell2_description = wan_descriptions[x]>
   </#if>
   <#assign isSecondCell = "true">
   <#assign secondCellPriority = x + 1>
   <#assign priorityIfNameTable += [cell_if2]>
   <#assign isTunnelEnabledTable += [far.enableTunnelOverCell2!"false"]>
   <#assign isCellIntTable += ["true"]>
   <#assign Cell2PortPriority = 100+x>
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
      ip route 0.0.0.0 0.0.0.0 ${priorityIfNameTable[p]} ${70+p} track ${p+40}
      ip route ${ipslaDestIPaddress[p]} 255.255.255.255 ${priorityIfNameTable[p]} track ${p+10}
    <#else>
      ip route 0.0.0.0 0.0.0.0 ${priorityIfNameTable[p]} dhcp ${70+p}
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
      <#-- config below is disabled until CSCvw77702 is fixed on both IOS and IOS-XE
           "'no ip dhcp client route track' should removed tracked object immediately"
           int ${priorityIfNameTable[p]}
             ip dhcp client route track ${p+40}
      -->
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
    <#if isUmbrella == "true">
      umbrella out
    </#if>
    <#if isTunnelEnabledTable[p] == "true" && isPrimaryHeadEndEnable == "true">
      crypto ikev2 client flexvpn ${vpnTunnelIntf}
      source ${p+1} ${priorityIfNameTable[p]} track ${p+40}
      <#if isCellIntTable[p] != "true">
        <#assign suffix = "dhcp">
      <#else>
        <#assign track_num = p + 40>
        <#assign suffix = "track " + track_num>
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

<#-- Umbrella DNS -->
<#if isUmbrella == "true">
crypto pki trustpoint umbrella
 revocation-check none
crypto pki certificate chain umbrella
 certificate ca 01FDA3EB6ECA75C888438B724BCFBC91
  30820494 3082037C A0030201 02021001 FDA3EB6E CA75C888 438B724B CFBC9130
  0D06092A 864886F7 0D01010B 05003061 310B3009 06035504 06130255 53311530
  13060355 040A130C 44696769 43657274 20496E63 31193017 06035504 0B131077
  77772E64 69676963 6572742E 636F6D31 20301E06 03550403 13174469 67694365
  72742047 6C6F6261 6C20526F 6F742043 41301E17 0D313330 33303831 32303030
  305A170D 32333033 30383132 30303030 5A304D31 0B300906 03550406 13025553
  31153013 06035504 0A130C44 69676943 65727420 496E6331 27302506 03550403
  131E4469 67694365 72742053 48413220 53656375 72652053 65727665 72204341
  30820122 300D0609 2A864886 F70D0101 01050003 82010F00 3082010A 02820101
  00DCAE58 904DC1C4 30159035 5B6E3C82 15F52C5C BDE3DBFF 7143FA64 2580D4EE
  18A24DF0 66D00A73 6E119836 1764AF37 9DFDFA41 84AFC7AF 8CFE1A73 4DCF3397
  90A29687 53832BB9 A675482D 1D56377B DA31321A D7ACAB06 F4AA5D4B B74746DD
  2A93C390 2E798080 EF13046A 143BB59B 92BEC207 654EFCDA FCFF7AAE DC5C7E55
  310CE839 07A4D7BE 2FD30B6A D2B1DF5F FE577453 3B3580DD AE8E4498 B39F0ED3
  DAE0D7F4 6B29AB44 A74B5884 6D924B81 C3DA738B 12974890 0445751A DD373197
  92E8CD54 0D3BE4C1 3F395E2E B8F35C7E 108E8641 008D4566 47B0A165 CEA0AA29
  094EF397 EBE82EAB 0F72A730 0EFAC7F4 FD1477C3 A45B2857 C2B3F982 FDB74558
  9B020301 0001A382 015A3082 01563012 0603551D 130101FF 04083006 0101FF02
  0100300E 0603551D 0F0101FF 04040302 01863034 06082B06 01050507 01010428
  30263024 06082B06 01050507 30018618 68747470 3A2F2F6F 6373702E 64696769
  63657274 2E636F6D 307B0603 551D1F04 74307230 37A035A0 33863168 7474703A
  2F2F6372 6C332E64 69676963 6572742E 636F6D2F 44696769 43657274 476C6F62
  616C526F 6F744341 2E63726C 3037A035 A0338631 68747470 3A2F2F63 726C342E
  64696769 63657274 2E636F6D 2F446967 69436572 74476C6F 62616C52 6F6F7443
  412E6372 6C303D06 03551D20 04363034 30320604 551D2000 302A3028 06082B06
  01050507 0201161C 68747470 733A2F2F 7777772E 64696769 63657274 2E636F6D
  2F435053 301D0603 551D0E04 1604140F 80611C82 3161D52F 28E78D46 38B42CE1
  C6D9E230 1F060355 1D230418 30168014 03DE5035 56D14CBB 66F0A3E2 1B1BC397
  B23DD155 300D0609 2A864886 F70D0101 0B050003 82010100 233EDF4B D23142A5
  B67E425C 1A44CC69 D168B45D 4BE00421 6C4BE26D CCB1E097 8FA65309 CDAA2A65
  E5394F1E 83A56E5C 98A22426 E6FBA1ED 93C72E02 C64D4ABF B042DF78 DAB3A8F9
  6DFF2185 5336604C 76CEEC38 DCD65180 F0C5D6E5 D44D2764 AB9BC73E 71FB4897
  B8336DC9 1307EE96 A21B1815 F65C4C40 EDB3C2EC FF71C1E3 47FFD4B9 00B43742
  DA20C9EA 6E8AEE14 06AE7DA2 599888A8 1B6F2DF4 F2C9145F 26CF2C8D 7EED37C0
  A9D539B9 82BF190C EA34AF00 2168F8AD 73E2C932 DA38250B 55D39A1D F06886ED
  2E4134EF 7CA5501D BF3AF9D3 C1080CE6 ED1E8A58 25E4B877 AD2D6EF5 52DDB474
  8FAB492E 9D3B9334 281F78CE 94EAC7BD D3C96D1C DE5C32F3
        quit

!
parameter-map type regex dns_bypass
pattern .*\.cisco\..*
<#if far.umbrellaDnsBypassList?has_content>
  <#list far.umbrellaDnsBypassList as patterns>
    pattern ${patterns['umbrellaDnsBypassDomain']}
  </#list>
</#if>
!
parameter-map type umbrella global
<#if UmbrellaToken?has_content>
  token ${UmbrellaToken}
</#if>

local-domain dns_bypass
dnscrypt
udp-timeout 5
!
no ip dns server
!
interface Vlan1
  ip nbar protocol-discovery
!
</#if>

<#-- Zone based firewall.  Expands on Bootstrap config -->

ip access-list extended eCVD-deny-from-outside

<#assign count = 10>
<#if far.firewallIp?has_content>
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
<#if isSecondCell == "true">
int ${cell_if2}
  zone-member security INTERNET
  !
</#if>
!

<#-- QoS config for IOS-XE -->

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
      class-map match-any CLASS-GOLD-SILVER-BRONZE
      <#list qosPolicyTable as QOS>
        <#if QOS['qosType']?has_content>
          <#if QOS['qosPriority'] == "med" || QOS['qosPriority'] == "low" || QOS['qosPriority'] == "hi">
            match protocol attribute traffic-class ${QOS['qosType']}
          </#if>
        </#if>
      </#list>
!
      policy-map SUB-CLASS-GOLD-SILVER-BRONZE
        class CLASS-GOLD
         priority level 1 percent 10

        class CLASS-SILVER
         bandwidth percent 50
!
        class CLASS-BRONZE
         bandwidth percent 40
!
      policy-map CELL_WAN_QOS

        class CLASS-GOLD-SILVER-BRONZE
          <#-- calculate based on total upstream throughput in bps -->
          <#assign qbw = QOSbw * 1000>
          shape average ${qbw?int?c}
          bandwidth remaining ratio 3
          service-policy SUB-CLASS-GOLD-SILVER-BRONZE
        class class-default
          fair-queue
          random-detect dscp-based
          bandwidth remaining ratio 1

      <#if isFirstCell?has_content && isFirstCell == "true">
        interface ${cell_if1}
          service-policy output CELL_WAN_QOS
      </#if>

      <#if isSecondCell?has_content && isSecondCell == "true">
        interface ${cell_if2}
          service-policy output CELL_WAN_QOS
      </#if>

    </#if>
  </#if>
</#if>

<#-- --- END OF QoS CONFIG ----------------------------- -->
!
<#-- IoT OD location tracking magic -->
<#if config.enableLocationTracking>
  event manager environment _gps_poll_interval ${config.locStreamRate}
  event manager environment _gps_threshold ${config.distThreshold}
  event manager policy fnd-push-gps.tcl type user
  event manager applet GNSS_ENABLE
  event timer cron cron-entry "*/1 * * * *"
  action 010 cli command "enable"
  action 020 cli command "show ${cell_if1} firmware"
  action 030 regexp "Modem is still down, please wait for modem to come up" $_cli_result match
   action 031 if $_regexp_result eq 1
   action 032 syslog msg  "Modem is DOWN, not touching anything and exiting"
   action 033 exit
  action 034 end
  action 035 cli command "show ${cell_if1} gps"
  ! action 036 syslog msg  "FULL OUTPUT: $_cli_result"
  action 040 foreach line $_cli_result "\r\n"
  !  action 045 syslog msg  "PROCESSING LINE '$line'"
   action 050 regexp "^GPS Mode Configured =[ ]+(.+)$" $line match _gps_mode
   action 060 if $_regexp_result eq 1
     ! action 070 syslog msg  "GPS MODE $_gps_mode"
     action 080 if $_gps_mode eq "not configured"
       action 090 syslog msg  "Enabling GPS standalone mode"
       action 100 cli command "conf t"
       action 110 cli command "controller ${cell_if1}"
       action 120 cli command "lte gps mode standalone"
       action 130 cli command "lte gps nmea"
       action 140 cli command "service internal"
       action 150 cli command "do test ${cell_if1} modem-power-cycle"
       action 160 cli command "end"
       action 170 break
     action 180 end
     action 190 if $_gps_mode eq "Modem reset/power-cycle is needed to change GPS Mode to not configured"
       action 200 syslog msg  "LTE module being power-cycled"
       action 210 cli command "conf t"
       action 220 cli command "service internal"
       action 230 cli command "do test ${cell_if1} modem-power-cycle"
       action 240 cli command "end"
       action 250 break
     action 260 end
   action 270 end
   action 300 regexp "^GPS Status =[ ]+(.+)$" $line match _gps_status
   action 310 if $_regexp_result eq 1
     ! action 320 syslog msg "GPS STATUS '$_gps_status'"
     action 330 if $_gps_status eq "NMEA Disabled"
       action 340 syslog msg "Configuring NMEA mode on GPS"
       action 350 cli command "conf t"
       action 360 cli command "controller ${cell_if1}"
       action 370 cli command "lte gps nmea"
       action 380 break
     action 390 end
   action 400 end
  action 410 end
</#if>
!
<#if isFirstCell == "true">
interface ${cell_if1}
    ip address negotiated
    dialer in-band
    dialer idle-timeout 0
    dialer-group 1
    pulse-time 1
</#if>
!
<#if isSecondCell == "true">
interface ${cell_if2}
    ip address negotiated
    dialer in-band
    dialer idle-timeout 0
    dialer-group 1
    pulse-time 1
    no shutdown
</#if>
!
interface Vlan1
ip address ${far.dhcpIPAddress} ${far.dhcpNetmask}
ip nbar protocol-discovery
ip nat inside
ip verify unicast source reachable-via rx
<#if isUmbrella == "true">
   umbrella in my_tag
</#if>
<#if helper_address?has_content>
  ip helper-address ${helper_address}
  no shutdown
<#else>
  no shutdown
  ip dhcp pool subtended
  network ${lanNtwk} ${far.dhcpNetmask}
  default-router ${far.dhcpIPAddress}
  dns-server ${DNSIP}
  lease 0 0 10
!
  <#if far.dhcpExcludeRangeStart?has_content && far.dhcpExcludeRangeEnd?has_content>
    ip dhcp excluded-address ${far.dhcpExcludeRangeStart} ${far.dhcpExcludeRangeEnd}
  </#if>
</#if>
!
!
<#-- enabling/disabling of ethernet ports -->

interface FastEthernet0/0/1
  description ${fastEth1Des}
<#if FastEthernet1_enabled != "true">
    shutdown
<#else>
	no shutdown
</#if>
!
interface FastEthernet0/0/2
  description ${fastEth2Des}
<#if FastEthernet2_enabled != "true">
    shutdown
<#else>
	no shutdown
</#if>
!
interface FastEthernet0/0/3
  description ${fastEth3Des}
<#if FastEthernet3_enabled != "true">
    shutdown
<#else>
	no shutdown
</#if>
!
interface FastEthernet0/0/4
  description ${fastEth4Des}
<#if FastEthernet4_enabled != "true">
    shutdown
<#else>
	no shutdown
</#if>

<#-- Setting Descriptions of WAN links -->

<#if wan_eth_description != "">
  interface ${ether_if}
    description ${wan_eth_description}
</#if>

<#if wan_cell1_description != "">
  interface ${cell_if1}
    description ${wan_cell1_description}
</#if>

<#if wan_cell2_description != "">
  interface ${cell_if2}
    description ${wan_cell2_description}
</#if>

<#-- Enable NAT and routing -->
<#assign gwips = far.dhcpIPAddress?split(".")>
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
<#-- ADDED 3 LINES BELOW FOR ADVANCED -->
<#if isSecondCell == "true">
route-map RM_WAN_ACL3 permit 10
    match ip address NAT_ACL
    match interface ${cell_if2}
</#if>
!
ip forward-protocol nd
!
<#if isFirstCell == "true">
ip nat inside source route-map RM_WAN_ACL interface ${cell_if1} overload
</#if>
ip nat inside source route-map RM_WAN_ACL2 interface ${ether_if} overload
<#-- ADDED 1 LINES BELOW FOR ADVANCED -->
<#if isSecondCell == "true">
ip nat inside source route-map RM_WAN_ACL3 interface ${cell_if2} overload
</#if>

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

! Remove routes from Bootstrap that we don't want
event manager applet remove-cell0-route-failproof-cli
  event timer countdown time 15
  action 600 cli command "enable"
  action 610 cli command "conf t"
  action 620 cli command "no ip route 0.0.0.0 0.0.0.0 ${cell_if1} 100"
  action 630 cli command "no event manager applet remove-cell0-route-failproof-cli"
  action 640 cli command "exit"
  action 650 cli command "write mem"

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
        <#case "cell_if2">
          <#assign dst_intf = cell_if2!"">
          <#break>
        <#case "VPN">
          <#assign dst_intf = vpnTunnelIntf!"">
          <#break>
        <#case "WGB">
          <#assign dst_intf = wgb_if!"">
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

interface Async0/2/0
  no ip address
  encapsulation relay-line
!
line vty 0 4
    exec-timeout 5 0
    length 0
    transport input ssh
!
!
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


<#if isFirstCell == "true" && APN1?has_content>
  <#-- if fist cell is enabled and there is an APN set -->
  <#-- get the current APN set for first cell interface -->
  event manager applet change_apn_cell1
  event timer countdown time 120
  action 005 set _match1 ""
  action 010 syslog msg "Verifying APN Profile"
  action 020 cli command "enable"
  action 030 cli command "show ${cell_if1} profile | i Access Point Name"
  action 040 regexp "^.* = ([A-Za-z0-9\.]+)" $_cli_result _match _match1
  action 050 if $_regexp_result eq 1
  action 060 syslog msg  "Current APN in ${cell_if1} is $_match1"
  action 070 end
  <#-- compare APN of first cell int with APN configured in IoT OD -->
  action 080 if $_match1 eq "${APN1}"
  <#-- already set, no change -->
  action 090 syslog msg  "APN is already set to $_match1"
  action 100 else
  action 110 syslog msg  "changing APN to ${APN1}"
  <#-- configure new APN, interface will be down 10-20 seconds -->
  action 120 cli command "${cell_if1} lte profile create 1 ${APN1}" pattern "confirm"
  action 130 cli command "y"
  action 140 end
</#if>
!
<#if isSecondCell == "true" && APN2?has_content>
  <#-- if second cell is enabled and there is an APN set -->
  <#-- get the current APN set for second cell interface -->
  event manager applet change_apn_cell2
  event timer countdown time 120
  action 005 set _match1 ""
  action 010 syslog msg "Verifying APN Profile"
  action 020 cli command "enable"
  action 030 cli command "show ${cell_if2} profile | i Access Point Name"
  action 040 regexp "^.* = ([A-Za-z0-9\.]+)" $_cli_result _match _match1
  action 050 if $_regexp_result eq 1
  action 060 syslog msg  "Current APN in ${cell_if2} is $_match1"
  action 070 end
  <#-- compare APN of first cell int with APN configured in IoT OD -->
  action 080 if $_match1 eq "${APN2}"
  <#-- already set, no change -->
  action 090 syslog msg  "APN is already set to $_match1"
  action 100 else
  action 110 syslog msg  "changing APN to ${APN2}"
  <#-- configure new APN, interface will be down 10-20 seconds -->
  action 120 cli command "${cell_if2} lte profile create 1 ${APN2}" pattern "confirm"
  action 130 cli command "y"
  action 140 end
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

! GW Recovery Scripts
!
<#if section.devicesettings_recovery?has_content && section.devicesettings_recovery == "true">
  <#if !far.recoveryTimer?has_content>
    <#assign recoveryTime = 120>
  <#else>
    <#assign recoveryTime = far.recoveryTimer>
  </#if>
  <#assign recoveryTimeIOTD = (recoveryTime?number / 2)?round>
!
track 88 interface Tunnel1 line-protocol
event manager environment outage_total_limit ${recoveryTime}
event manager environment outage_iotd_limit ${recoveryTimeIOTD}
event manager environment outage_current 0
!
event manager applet CHECK_IOTD_RECOVERY_STATUS
  description "Check if connectivity is still lost"
  event timer watchdog time 60 maxrun 99
  action 1.0  cli command "enable"
  action 2.0  track read 88
  action 3.0  if $_track_state eq "down"
  action 4.0    counter name "current_iotd_outage" op inc value 1
  action 5.0    comment syslog msg "IOTD Connectivity failure. Outage increased to:  $_counter_value_remain"
  action 5.1    cli command "config t"
  action 5.2    cli command "event manager environment outage_current $_counter_value_remain"
  action 6.0  end
!
event manager applet RESET_IOTD_RECOVERY_COUNTER
  description "Reset counter when IOTD connectivity is restored."
  event track 88 state up maxrun 99
  action 1.0  cli command "enable"
  action 2.0  syslog msg "Connectivity restored. Clearing GW recovery counter."
  action 3.0  counter name "current_iotd_outage" op set value 0
  action 3.1  cli command "config t"
  action 3.2  cli command "event manager environment outage_current 0"
!
event manager applet INITIATE_GW_RECOVERY
  description "Clear running config and register GW with IOTD if WAN connectivity lost > timer set"
  event counter name current_iotd_outage entry-val ${recoveryTimeIOTD} entry-op ge exit-op ge exit-val ${recoveryTime} maxrun 360
  action 1.0  counter name "current_iotd_outage" op nop
  action 2.0  syslog msg "IOTD current outage is: $_counter_value_remain. Checking total outage timer."
  action 3.0  if $_counter_value_remain gt $outage_total_limit
  action 3.1    syslog msg "Both timers expired. Will initiate GW recovery."
  action 3.2    counter name "current_iotd_outage" op set value 0
  action 3.3    cli command "enable"
  action 3.4    syslog msg "Recovery Script STARTING collection of data"
  action 4.0    cli command "show romvar | redirect flash:iotd_recovery.log" pattern "confirm|#"
  action 4.1    cli command ""
  action 4.2    syslog msg "STARTING dir /all /recursive all-filesystems "
  action 4.3    cli command "dir /all /recursive all-filesystems | append bootflash:iotd_recovery.log" pattern "#"
  action 4.4    syslog msg "STARTING show pnp tech-support "
  action 4.5    cli command "show pnp tech-support | append bootflash:iotd_recovery.log" pattern "#"
  action 4.6    cli command "show clock detail | append bootflash:iotd_recovery.log" pattern "#"
  action 4.7    syslog msg "STARTING show tech-support "
  action 4.8    cli command "show tech-support | append bootflash:iotd_recovery.log" pattern "#"
  action 4.9    cli command "show clock detail | append bootflash:iotd_recovery.log" pattern "#"
  action 5.0    syslog msg "STARTING show show logging "
  action 5.1    cli command "show logging | append bootflash:iotd_recovery.log" pattern "#"
  action 5.2    syslog msg "Recovery Script FINISHED collecting"
  action 5.3    cli command "dir bootflash:/managed/bypass-discovery.cfg | inc 2609"
  action 5.4    regexp "-rw-" "$_cli_result"
  action 6.0    if $_regexp_result eq "0"
  action 6.1      syslog msg "*** bypass-discovery.cfg NOT found in bootflash:/managed, will attempt pnp reset ***"
  action 6.2      cli command "pnpa service reset no-prompt"
  action 6.3      reload
  action 6.4    else
  action 6.5      syslog msg "*** bypass-discovery.cfg FOUND in bootflash:/managed, performing reset ***"
  action 6.6      cli command "copy flash:/managed/bypass-discovery.cfg startup-config" pattern "startup-config|#"
  action 6.7      cli command ""
  action 6.8      wait 10
  action 6.9      reload
  action 7.0    end
  action 7.1  else
  action 7.2    syslog msg "IOTD not reachable, but total outage limit $outage_total_limit not reached yet."
  action 7.3    break
  action 7.4  end
</#if>



</#compress>

<#-- End eCVD template -->
