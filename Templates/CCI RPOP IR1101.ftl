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
<#-- Version 1.0         -->

<#-- Default BootStrap Configuration -->

<#assign sublist 		= "${far.eid}"?split("+")[0..1]>
<#assign pid = sublist[0]>
<#assign model = pid[0..4]>
<#assign sn = sublist[1]>

<#assign model = "IR1101">
<#assign ether_if = "GigabitEthernet 0/0/0">
<#assign cell_if = "Cellular 0/1/0">

<#-- Interface Menu -->
<#assign FastEthernet1 = "${far.fastEthernet1}">
<#assign FastEthernet2 = "${far.fastEthernet2}">
<#assign FastEthernet3 = "${far.fastEthernet3}">
<#assign FastEthernet4 = "${far.fastEthernet4}">

<#-- WAN Menu -->
<#if far.apn?has_content>
<#assign APN			= "${far.apn}">
</#if>

<#-- LAN Menu -->
<#assign lanIP 		= "${far.lanIPAddress}"?split(".")>
<#assign lanNet 	= "${far.lanNetmask}"?split(".")>

<#-- VPN Settings Menu -->
<#assign herIpAddress 	= "${far.herIpAddress}">
<#assign herPsk			= "${far.herPsk}">

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

<#assign  lan_ip=[]  lan_netmask=[]>

<#-- Binary Conversion of LAN IP-->

<#list lanIP as lann> 
<#assign lan=lann?number>
<#list 1..100 as y>
<#if lan < 1> 
<#if lan == 0>
<#list 1..8 as s> <#assign lan_ip=lan_ip+["0"]> </#list> </#if>
<#if lan_ip?size % 8 != 0> <#list 1..8 as s> <#assign lan_ip=lan_ip+["0"]> <#if lan_ip?size % 8 == 0> <#break> </#if> </#list> </#if>
<#assign ip_bit = lan_ip?reverse> <#break> </#if>

<#assign x=lan%2 st=x?string lan_ip=lan_ip+[st] lan=lan/2> </#list></#list>

<#-- Binary Conversion of NetMask-->

<#list lanNet as lann> 
<#assign lan=lann?number>
<#list 1..100 as y>
<#if lan < 1 >
<#if lan == 0>
<#list 1..8 as s> <#assign lan_netmask=lan_netmask+["0"]> </#list> </#if>
<#if lan_netmask?size % 8 != 0>
<#list 1..8 as s> <#assign lan_netmask=lan_netmask+["0"]> <#if lan_netmask?size % 8 == 0> <#break>
</#if> </#list> </#if>
<#assign subnet_bit= lan_netmask?reverse> <#break> </#if>

<#assign x=lan%2 st=x?string lan_netmask=lan_netmask+[st] lan=lan/2> </#list> </#list>

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



service timestamps debug datetime msec
service timestamps log datetime msec
service call-home
platform qfp utilization monitor load 80
no platform punt-keepalive disable-kernel-core
!
!
clock timezone ${clockTZ} ${offset}
ntp server ${ntpIP}
!
ip name-server ${DNSIP}
ip domain name ${domainName}
!
!
no aaa new-model
!
!
!
!
!
!
!
ip host cci-fnd-oracle.cimconccibgl.cisco.com 10.10.100.90
ip host rsaca.cimconccibgl.cisco.com 172.17.70.10
no ip domain lookup
ip domain name ${domainName}
!
!
!
login on-success log
ipv6 unicast-routing
!
!
!
!
!
!
!
<#-- Virtual Networks-->

<#assign vnNumber = 101>
<#list far.VirtualNetworks as VN>
  <#if VN['vnName']?has_content>
      vrf definition ${VN['vnName']}
       rd 1:4${vnNumber}
       !
       address-family ipv4
        import ipv4 unicast map SS-NETWORK-TO-VRF
        route-target export 1:4${vnNumber}
        route-target import 1:4${vnNumber}
       exit-address-family
      !
      interface Tunnel${vnNumber}
       description Tunnel for ${VN['vnName']}
       vrf forwarding ${VN['vnName']}
       ip address ${VN['vnTunnelLocalIP']} 255.255.255.0
       no ip redirects
       ip nhrp map ${VN['vnNHRPip']} ${VN['vnNHRPnbmaIP']}
       ip nhrp network-id ${vnNumber}
       ip nhrp nhs ${VN['vnNHRPip']}
       ip nhrp registration timeout 30
       tunnel source Loopback${vnNumber}
       tunnel mode gre multipoint
      !
      interface Vlan${vnNumber}
       vrf forwarding ${VN['vnName']}
       ip address 172.10.25.1 255.255.255.0
       ip helper-address 10.10.100.20
      !
      router bgp 65550
       bgp log-neighbor-changes
       !
       address-family ipv4 vrf ${VN['vnName']}
        redistribute connected
        redistribute static
        neighbor ${VN['vnNHRPip']} remote-as 65550
        neighbor ${VN['vnNHRPip']} update-source Tunnel${vnNumber}
        neighbor ${VN['vnNHRPip']} activate
       exit-address-family
       !
      interface Loopback${vnNumber}
       description Tunnel${vnNumber} source IP
       ip address 10.22.22.${vnNumber}
      !
      !
      ip access-list standard FlexVPN_Client_Default_IPv4_Route
       permit 10.22.22.${vnNumber}
       permit 10.254.254.${vnNumber}
      !
       <#assign vnNumber = vnNumber + 1>
   </#if>
</#list>

!
!
!
!
!
!
!
!
!
!
!
crypto pki trustpoint SLA-TrustPoint
 enrollment pkcs12
 revocation-check crl
!
crypto pki trustpoint TP-self-signed-49885493
 enrollment selfsigned
 subject-name cn=IOS-Self-Signed-Certificate-49885493
 revocation-check none
 rsakeypair TP-self-signed-49885493
!
crypto pki trustpoint LDevID
 enrollment retry count 4
 enrollment retry period 2
 enrollment mode ra
 enrollment profile LDevID
 serial-number none
 fqdn none
 ip-address none
 password
 fingerprint 9F069AEA02B6E0B438C6E545169E76846020D5EF
 subject-name serialNumber=PID: ${model} SN:${sn},CN= ${model}_${sn}.{domainName}
 revocation-check none
 rsakeypair LDevID 2048
!
crypto pki profile enrollment LDevID
 enrollment url  http://rsaca.cimconccibgl.cisco.com/certsrv/mscep/mscep.dll
!
!
license boot level network-advantage
diagnostic bootup level minimal
!
spanning-tree extend system-id
memory free low-watermark processor 50261
!
!
<#list far.Users as user >
		username ${user['userName']} privilege ${user['userPriv']} algorithm-type scrypt secret ${user['userPassword']}
</#list> 
!
redundancy
!
!
crypto ikev2 authorization policy FlexVPN_Author_Policy
 route set interface
 route set access-list FlexVPN_Client_Default_IPv4_Route
 route set access-list ipv6 FlexVPN_Client_Default_IPv6_Route
!
crypto ikev2 proposal FlexVPN_IKEv2_Proposal_Cert
 encryption aes-cbc-256
 integrity sha256
 group 14
!
crypto ikev2 policy FlexVPN_IKEv2_Policy_Cert
 proposal FlexVPN_IKEv2_Proposal_Cert
!
!
crypto ikev2 profile FlexVPN_IKEv2_Profile_Cert
 match identity remote fqdn CCI-HER-1
 identity local fqdn spoke-18-flexVPN
 authentication remote rsa-sig
 authentication local rsa-sig
 pki trustpoint LDevID
 dpd 120 3 periodic
 aaa authorization group cert list FlexVPN_Author FlexVPN_Author_Policy
!
crypto ikev2 fragmentation
crypto ikev2 client flexvpn FlexVPN_Client
  peer 1 ${herIpAddress}
  client connect Tunnel100
!
!
controller Cellular 0/1/0
!
controller Cellular 0/3/0
!
!
vlan internal allocation policy ascending
!
vlan 1022
lldp run
!
!
!
!
!
!
!
crypto isakmp invalid-spi-recovery
!
!
crypto ipsec transform-set FlexVPN_IPsec_Transform_Set esp-aes esp-sha-hmac
 mode transport
!
crypto ipsec profile FlexVPN_IPsec_Profile_Cer
 set transform-set FlexVPN_IPsec_Transform_Set
 set pfs group14
 set ikev2-profile FlexVPN_IKEv2_Profile_Cert
!
!
!
!
!
!
!
!
interface Loopback39
 ip address 192.168.200.39 255.255.255.0
 ipv6 address 2001:DB8:BABA:FACE::39/64
 ipv6 enable
!

interface Tunnel100
 ip unnumbered Loopback39
 ipv6 unnumbered Loopback39
 tunnel source Cellular0/1/0
 tunnel destination dynamic
 tunnel protection ipsec profile FlexVPN_IPsec_Profile_Cer
!
interface GigabitEthernet0/0/0
 switchport
 switchport access vlan 125
 switchport mode access
 media-type rj45
!
interface FastEthernet0/0/1
 switchport access vlan 1022
 switchport mode access
<#if FastEthernet1 != "true">
    shutdown
<#else>
	no shutdown
</#if>
!
interface FastEthernet0/0/2
<#if FastEthernet2 != "true">
    shutdown
<#else>
	no shutdown
</#if>
!
interface FastEthernet0/0/3
 switchport access vlan 425
 switchport mode access
<#if FastEthernet3 != "true">
    shutdown
<#else>
	no shutdown
</#if>
!
interface FastEthernet0/0/4
 switchport access vlan 225
 switchport mode access
<#if FastEthernet4 != "true">
    shutdown
<#else>
	no shutdown
</#if>
!
interface GigabitEthernet0/0/5
!
interface Cellular0/1/0
 description Cellular Connection to Firewall Public IP
 mtu 1430
 ip address negotiated
 dialer in-band
 dialer idle-timeout 0
 dialer watch-group 1
 dialer-group 1
 ipv6 enable
 pulse-time 1
 ip virtual-reassembly
!
interface Cellular0/1/1
 no ip address
!
interface Cellular0/3/0
 no ip address
 shutdown
!
interface Cellular0/3/1
 no ip address
 shutdown
!
interface Vlan1
 no ip address
!
!
interface Async0/2/0
 no ip address
 encapsulation scada
!
ip forward-protocol nd
!
ip http server
ip http authentication local
ip http secure-server
ip route 0.0.0.0 0.0.0.0 Cellular0/1/0
!
!
!
!
dialer-list 1 protocol ip permit
dialer-list 1 protocol ipv6 permit
!
!
!
!
!
control-plane
!
!
!
line con 0
 exec-timeout 0 0
 stopbits 1
 speed 115200
line 0/0/0
line 0/2/0
line vty 0 4
 login
 transport input ssh
line vty 5 14
 login
 transport input ssh
!
call-home
 ! If contact email address in call-home is configured as sch-smart-licensing@cisco.com
 ! the email address configured in Cisco Smart License Portal will be used as contact email address to send SCH notifications.
 contact-email-addr sch-smart-licensing@cisco.com
 profile "CiscoTAC-1"
  active
  destination transport-method http
!
!
!
!
!
!
!
!
!
!
end



<#-- End eCVD template -->

<#elseif far.isRunningCgOs()>

<#else>
  ${provisioningFailed("FAR is not running CG-OS or IOS")}
</#if>
                     
        
