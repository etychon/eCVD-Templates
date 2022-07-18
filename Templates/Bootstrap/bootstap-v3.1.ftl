<#-- Default BootStrap Configuration -->
<#if far.isRunningIos()>
    <#assign sublist = far.eid?split("+")[0..1]>
    <#assign pid = sublist[0]>
    <#assign model = pid[0..4]>
<#if isRollbackConfig?has_content && isRollbackConfig == true>
    event manager applet iotocrollback
     event timer countdown time 5 maxrun 99
     action 1 cli command "enable"
    <#if model == "IR829">
        action 2 cli command "service-module wlan-ap 0 reset default-config"
    <#elseif model == "IR182" || model == "IR183">
        action 2.0 cli command "hw-module subslot 0/3 error-recovery password_reset"
        action 2.1 wait 30
        action 2.2 cli command "hw-module subslot 0/3 reload force"
    </#if>
     action 3.1 cli command "delete /f flash:express-setup-config*"
     action 3.2 cli command "delete /f flash:before-registration-config*"
     action 3.3 cli command "delete /f flash:before-tunnel-config*"
     action 3.4 cli command "delete /f flash:/-*"
     action 4 cli command "erase nvram:" pattern "confirm|#"
     action 5 cli command ""
     action 6 reload

<#else>
  <#assign herip = nms.herIP>
  <#assign her_name = nms.herHost>
  <#assign iotserver = nms.host>
<#-- Set the following to false if using IR829 with SFP on Gi0 -->
  <#assign ir829_use_gi1 = true>
  <#assign gwips = far.ip?split(".")>
  <#assign nwk_suffix = (gwips[3]?number / 32)?int * 32>
  <#assign nwk_addr = gwips[0] + "." + gwips[1] + "." + gwips[2] + "." + nwk_suffix>
  <#assign ap_if_nwk = gwips[0] + "." + gwips[1] + "." + gwips[2] + "." + (nwk_suffix + 4)>
  <#assign ap_if_addr = gwips[0] + "." + gwips[1] + "." + gwips[2] + "." + (nwk_suffix + 5)>
  <#assign sn = sublist[1]>
<#-- Set ip addresses and subnets for IOx -->
  <#assign iox_subnet = gwips[0] + "." + gwips[1] + "." + gwips[2] + "." + (nwk_suffix + 16)>
  <#assign gos_if_addr = gwips[0] + "." + gwips[1] + "." + gwips[2] + "." + (nwk_suffix + 17)>
  <#assign gos_addr = gwips[0] + "." + gwips[1] + "." + gwips[2] + "." + (nwk_suffix + 18)>
<#-- Determine Ethernet WAN interface base on Model - 807, 809, 829 or 1101 -->
<#-- NOTE: No support for Dual LTE platform yet -->
  <#if model == "IR807">
    <#assign ether_if = "FastEthernet0">
    <#assign cell_if = "Cellular 0">
  <#elseif model == "IR110">
    <#assign model = "IR1101">
    <#assign ether_if = "GigabitEthernet0/0/0">
    <#assign cell_if = "Cellular 0/1/0">
    <#assign cell_if_contr = "Cellular 0/1/0">
  <#elseif model == "IR182" || model == "IR183">
    <#assign model = "IR1800">
    <#assign ether_if = "GigabitEthernet0/0/0">
    <#assign cell_if = "Cellular 0/4/0">
    <#assign cell_if_contr = "Cellular 0/4/0">
  <#else>
    <#if model == "IR829" && ir829_use_gi1>
      <#assign ether_if = "Vlan 10">
    <#else>
      <#assign ether_if = "GigabitEthernet0">
    </#if>
    <#assign cell_if = "Cellular 0/0">
    <#if pid?contains("2LTE")>
      <#if (far.cellularICCID3!?length == 19 || far.cellularICCID3!?length == 20) && !(far.cellularICCID1!?length == 19 || far.cellularICCID1!?length == 20)>
        <#assign cell_if = "Cellular 1/0">
      </#if>
    <#else>
      <#assign cell_if = "Cellular 0">
    </#if>
  </#if>

<#--Adding retry delays for PnP work response so that work response does not get missed if modem is reset -->
  do-exec pnp service internal 1
  do-exec pnp service wait-time 10 20 20
  do-exec pnp service internal 0

  banner login "Cisco IoT Gateway v3.1"
  hostname ${model}_${sn}
  alias exec cfgdiff show archive config differences nvram:startup-config system:running-config
  !
  boot-start-marker
  boot system ${far.imageFileInstalled}
  boot-end-marker
  !
  aaa new-model
  !
  aaa authentication login default local
  aaa authorization console
  aaa authorization exec default local
  aaa authorization network default local
  !
  username ${deviceDefault.adminUsername} privilege 15 algorithm-type scrypt secret ${deviceDefault.adminPassword}
  !
  default crypto ikev2 authorization policy
  crypto ikev2 authorization policy default
  route set interface
  route set access-list GWIPS
  !
  crypto ikev2 proposal iotod-dh-groups
  encryption aes-cbc-256 aes-cbc-192 aes-cbc-128
  integrity sha512 sha384 sha256 sha1 md5
  group 19 14 21 5
  exit
  !
  crypto ikev2 policy iotod-dh-groups
  match fvrf any
  proposal iotod-dh-groups
  exit
  !
  crypto ikev2 keyring Flex_key
  peer cloud-core-router
<#-- TODO: change according to cluster -->
  address ${herip}
  identity key-id cloud-core-router
  pre-shared-key ${deviceDefault.mgmtVpnPsk}
  !
  !
  crypto ikev2 profile Flex_IKEv2
  match identity remote key-id cloud-core-router
  identity local email ${sn}@ciscoiotdev.io
  authentication remote pre-share
  authentication local pre-share
  keyring local Flex_key
  dpd 29 2 periodic
  nat force-encap
  aaa authorization group psk list default default
  !
  default crypto ipsec profile
  crypto ipsec profile default
  set ikev2-profile Flex_IKEv2
  !
  vrf definition ciscoiot
  address-family ipv4
  !
  interface Loopback1
  vrf forwarding ciscoiot
  ip address ${far.ip} 255.255.255.255
  ip nat inside
  ip dns server
  !
<#if model == "IR829" && ir829_use_gi1>
  vlan 10
  int Vlan 10
  ip address dhcp
  int gi1
  switch access vlan 10
  int vlan 1
  no ip address
</#if>
<#if model == "IR829">
  do service-module wlan-ap 0 reset default-config
  vlan 20
  interface Vlan20
  vrf forwarding ciscoiot
  ip address ${ap_if_addr} 255.255.255.252
  interface Wlan-GigabitEthernet0
  switchport trunk native vlan 20
  switchport mode trunk
  interface wlan-ap0
  ip address 10.10.10.0 255.255.255.255
  no shut
  ip dhcp pool ap
  vrf ciscoiot
  network ${ap_if_nwk} 255.255.255.252
  dns-server ${ap_if_addr}
  default-router ${ap_if_addr}
</#if>
  interface Tunnel1
  vrf forwarding ciscoiot
  ip address negotiated
  ip mtu 1340
  ip tcp adjust-mss 1300
  tunnel source dynamic
  tunnel mode ipsec ipv4
  tunnel destination dynamic
  tunnel path-mtu-discovery
  tunnel protection ipsec profile default
  !
  snmp-server trap-source Loopback1
  ip route 0.0.0.0 0.0.0.0 ${ether_if} dhcp
  ip route ${herip} 255.255.255.255 ${ether_if} dhcp
  !
  track 1 interface ${ether_if} ip routing
  crypto ikev2 client flexvpn Tunnel1
  source 1 ${ether_if} track 1
  peer 1 ${herip}
  client connect Tunnel1
  !
  ip forward-protocol nd
  ip http authentication local
  ip http secure-server
  <#if pid?contains("IR8")>
    ip http secure-trustpoint CISCO_IDEVID_SUDI
    ip http secure-port 8443
  </#if>
  !
  ip access-list standard GWIPS
  permit ${nwk_addr} 0.0.0.31
  !
  <#if model == "IR1101">
    dialer watch-list 1 ip 5.6.7.8 0.0.0.0
    dialer watch-list 1 delay route-check initial 1
    dialer watch-list 1 delay connect 1
  </#if>
  dialer-list 1 protocol ip permit
  !
  zone security INTERNET
  zone security default
  !
  ip access-list extended Everything
   10 permit ip any any
  ip access-list extended filter-dhcp
   10 permit udp any eq bootpc host 255.255.255.255 eq bootps
   20 permit udp any eq bootps host 255.255.255.255 eq bootpc
  ip access-list extended filter-internet
  ip access-list extended filter-traceroute
   10 permit icmp any any host-unreachable
   20 permit icmp any any time-exceeded
   30 permit icmp any any unreachable
   40 permit icmp any any ttl-exceeded
  !
  class-map type inspect match-any Everything
   match access-group name Everything
  class-map type inspect match-any bypass-cm
   match access-group name filter-dhcp
   match access-group name filter-traceroute
  class-map type inspect match-any allowed-internet
   match access-group name filter-internet
   match protocol icmp
  !
  policy-map type inspect Any2SELF
   class type inspect bypass-cm
    pass
   class type inspect Everything
    inspect
   class class-default
  policy-map type inspect INTERNET2Any
   class type inspect bypass-cm
    pass
   class type inspect allowed-internet
    inspect
   class class-default
  policy-map type inspect StdPolicy
   class type inspect bypass-cm
    pass
   class type inspect Everything
    inspect
   class class-default
  !
  zone-pair security INTERNET-TO-SELF source INTERNET destination self
   service-policy type inspect INTERNET2Any
  zone-pair security INTERNET-TO-default source INTERNET destination default
   service-policy type inspect INTERNET2Any
  zone-pair security SELF-TO-INTERNET source self destination INTERNET
   service-policy type inspect StdPolicy
  zone-pair security SELF-TO-default source self destination default
   service-policy type inspect StdPolicy
  zone-pair security default-TO-INTERNET source default destination INTERNET
   service-policy type inspect StdPolicy
  zone-pair security default-TO-SELF source default destination self
   service-policy type inspect Any2SELF
  !
  int ${ether_if}
  zone-member security INTERNET
  !
  wsma agent exec
  profile exec
  wsma agent config
  profile config
  wsma profile listener exec
  transport https path /wsma/exec
  wsma profile listener config
  transport https path /wsma/config
  !
  cgna gzip
  !
  cgna profile cg-nms-register
  add-command show version | format flash:/managed/odm/cg-nms.odm
  add-command show inventory | format flash:/managed/odm/cg-nms.odm
  interval 3
  active
  url https://${iotserver}/cgna/ios/registration
  gzip
  !
  do del /f flash:/-*
  do del /f /r flash:/managed/accesspoint*
  archive
  path flash:/
  maximum 3
  !
<#-- Start of configuration needed to enable IOx -->
  ip access-list extended NAT_ACL
    permit ip ${iox_subnet} 0.0.0.7 any
  !
  ip dhcp pool ioxpool
 	  network ${iox_subnet} 255.255.255.248
 	  default-router ${gos_if_addr}
 	  dns-server ${gos_if_addr}
 	  remember
  !
  interface Loopback1
    ip policy route-map VRF_TO_GLOBAL
  !
  <#if model == "IR1101" || model == "IR1800">
   iox
   !
   interface VirtualPortGroup0
     description IOx Interface
     ip address ${gos_if_addr} 255.255.255.248
     ip nat inside
     ipv6 enable
   ip access-list standard IOxRange
     10 permit ${iox_subnet} 0.0.0.7
  <#elseif model == "IR829" || model == "IR809">
    <#if model == "IR829">
      <#assign gos_if = "GigabitEthernet5">
    <#else>
      <#assign gos_if = "GigabitEthernet2">
    </#if>

    ip host gos.iotspdev.local ${gos_addr}
    !
    interface ${gos_if}
	    ip address ${gos_if_addr} 255.255.255.248
      ip nat inside
      ip virtual-reassembly in
      duplex auto
      speed auto
      ipv6 enable
      no shutdown
      ip policy route-map GLOBAL_TO_VRF
      ip vrf receive ciscoiot
    iox client enable interface ${gos_if}

    ip access-list extended 133
      ! match GOS subnet
      10 permit ip any ${iox_subnet} 0.0.0.7

    ip access-list extended 140
      ! match loopback1 IP address
      10 permit ip any host ${far.ip}

    ip access-list extended 145
      ! match Tunnel1 subnet
      10 permit ip any 172.17.0.0 0.0.255.255

    ip access-list extended 148
      ! match cloud subnet
      10 permit ip any 10.0.0.0 0.0.3.255
      20 permit ip any 10.0.4.0 0.0.3.255
      30 permit ip any 10.0.8.0 0.0.3.255

    route-map VRF_TO_GLOBAL
      match ip address 133
      set global

    route-map GLOBAL_TO_VRF
      match ip address 140
      match ip address 145
      match ip address 148
      set vrf ciscoiot
  </#if>
<#-- End of configuration needed to enable IOx -->
  !
  line vty 0 99
   transport input none
  !
  event manager directory user policy "flash:/managed/scripts"
  event manager policy no_config_replace.tcl type system authorization bypass
<#-- apply cellular config via EEM since config causes PnP failure on IR1101-->
  event manager applet cell_pnp
  event timer watchdog time 20
  action 1 cli command "enable"
  action 2 cli command "conf t"
<#if pid?contains("2LTE")>
action 2.1 cli command "controller Cell 0"
<#else>
action 2.1 cli command "controller ${cell_if}"
</#if>
  action 2.2 cli command "src-ip-violation-action drop ipv4"
  action 2.3 cli command "int ${cell_if}"
  action 2.4 cli command "dialer in-band"
  action 2.5 cli command "dialer-group 1"
  action 2.6 cli command "zone-member security INTERNET"
  action 3 cli command "ip route 0.0.0.0 0.0.0.0 ${cell_if} 100"
  action 3.1 cli command "ip route ${herip} 255.255.255.255 ${cell_if} 10"
  action 4 cli command "track 2 interface ${cell_if} ip routing"
  action 5 cli command "crypto ikev2 client flexvpn Tunnel1"
  action 6 cli command "source 2 ${cell_if} track 2"
  action 7 cli command "no event manager applet cell_pnp"
  action 8 cli command "do wr"
  action 9.1 cli command "do del /f flash:/before-registration-config"
  action 9.2 cli command "do delete /f flash:/express-setup-config"

<#if model == "IR1101">
  event manager applet GPS_ENABLE_IR1100
  event timer watchdog time 60
  action 010 cli command "enable"
  action 020 cli command "show ${cell_if} firmware"
      action 030 regexp "Modem is still down, please wait for modem to come up" $_cli_result match
      action 040 if $_regexp_result eq 1
        action 050 syslog msg  "Modem is DOWN, exit without any changes"
        action 060 exit
      action 070 end
  action 080 cli command "show ${cell_if} hardware | inc Modem Firmware Version"
  action 090 regexp "^Modem Firmware Version =[ ]+SWI(.+)$" $_cli_result match _modem_version
  action 095 if $_regexp_result eq 1
      action 200 cli command "show ${cell_if} gps"
      action 201 foreach line $_cli_result "\r\n"
        action 202 regexp "^GPS Mode Configured =[ ]+(.+)$" $line match _gps_mode
        action 210 if $_regexp_result eq 1
          action 220 if $_gps_mode eq "not configured"
            action 221 syslog msg  "Enabling GPS standalone mode"
            action 222 cli command "conf t"
            action 230 cli command "controller ${cell_if_contr}"
            action 240 cli command "lte gps auto-reset"
            action 250 cli command "lte gps mode standalone"
            action 260 cli command "lte gps nmea"
            action 270 cli command "end"
            action 280 break
          action 300 elseif $_gps_mode eq "standalone"
            action 310 cli command "conf t"
            action 320 syslog msg "Removing GPS applet"
            action 330 cli command "no event manager applet GPS_ENABLE_IR1100"
            action 340 cli command "end"
          action 350 end
        action 370 end
      action 400 end
  action 500 else
    action 510 syslog msg "Not a Sierra Wireless modem"
    action 520 cli command "conf t"
    action 530 syslog msg "Removing GPS applet"
    action 540 cli command "no event manager applet GPS_ENABLE_IR1100"
    action 550 cli command "end"
  action 600 end
</#if>

<#if model == "IR1800">
  event manager applet GPS_ENABLE_IR1800
  event timer watchdog time 60
  action 010 cli command "enable"
  action 020 cli command "show ${cell_if} firmware"
      action 030 regexp "Modem is still down, please wait for modem to come up" $_cli_result match
      action 040 if $_regexp_result eq 1
        action 050 syslog msg  "Modem is DOWN, exit without any changes"
        action 060 exit
      action 070 end
  action 200 cli command "show ${cell_if} gps"
  action 201 foreach line $_cli_result "\r\n"
    action 202 regexp "^GPS Mode Configured =[ ]+(.+)$" $line match _gps_mode
    action 210 if $_regexp_result eq 1
      action 220 if $_gps_mode eq "not configured"
        action 221 syslog msg  "Enabling GPS standalone mode"
        action 222 cli command "conf t"
        action 230 cli command "controller ${cell_if_contr}"
        action 240 cli command "lte gps auto-reset"
        action 250 cli command "lte gps mode standalone"
        action 260 cli command "lte gps nmea"
        action 270 cli command "end"
        action 280 break
      action 300 elseif $_gps_mode eq "standalone"
        action 310 cli command "conf t"
        action 320 syslog msg "Removing GPS applet"
        action 330 cli command "no event manager applet GPS_ENABLE_IR1800"
        action 340 cli command "end"
      action 350 end
    action 370 end
  action 400 end
</#if>

  event manager applet updateSNMP
  event timer watchdog time 600
  action 10 cli command "enable"
  action 20 cli command "show run | i ^snmp-server host"
  action 30 set snmphosts "$_cli_result"
  action 40 cli command "conf t"
  action 41 foreach line "$snmphosts" "\n"
  action 42  string match "snmp-server*" "$line"
  action 43  if $_string_result ne "1"
  action 44   continue
  action 45  end
  action 46  cli command "no $line"
  action 49 end
  action 50 cli command "snmp-server host ${nms.snmpHost} vrf ciscoiot version 3 priv admin"
  action 51 string match "*Invalid*" "$_cli_result"
  action 52 if $_string_result eq "1"
  action 53  foreach line "$snmphosts" "\n"
  action 54   string match "*vrf*" "$line"
  action 55   if $_string_result eq "1"
  action 56    cli command "$line"
  action 57    break
  action 58   end
  action 59  end
  action 60 end

  track 111 interface Tunnel1 ip routing
  event man env herip ${herip}
  event manager applet MgmtTuRecvry
   event tag 1 track 111 state down maxrun 330
   event tag 2 counter name MgmtTuDwn entry-val 1 entry-op ge exit-val 1 exit-op ge
   event tag 3 timer cron cron-entry "@reboot"
   trigger
    correlate event 1 or event 2 or event 3
   action 10 track read 111
   action 11 if $_track_state eq "up"
   action 12  counter name "MgmtTuDwn" op set value 0
   action 13  exit
   action 14 end
   action 15 cli command "enable"
   action 16 cli command "ping 8.8.8.8 rep 1 time 0"
   action 20 cli command "conf t"
   action 21 cli command "crypto ikev2 client flexvpn Tunnel1"
   action 22 cli command "peer 1 fqdn ${her_name}"
   action 23 regexp "resolved to address: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\r" "$_cli_result" match newip
   action 24 if $_regexp_result eq "1"
   action 30  if $newip ne "$herip"
   action 31   cli command "crypto ikev2 keyring Flex_key"
   action 32   cli command "peer cloud-core-router"
   action 33   cli command "address $newip"
   action 34   cli command "ip route $newip 255.255.255.255 ${ether_if} dhcp"
   action 35   cli command "ip route $newip 255.255.255.255 ${cell_if} 10"
   action 36   cli command "no ip route $herip 255.255.255.255 ${ether_if} dhcp"
   action 37   cli command "no ip route $herip 255.255.255.255 ${cell_if} 10"
   action 50   cli command "event man env herip $newip"
   action 51   cli command "do wr"
   action 60  end
   action 70 end
   action 90 wait 300
   action 91 counter name "MgmtTuDwnRetry" op inc value 1
  event manager applet MgmtTuRecvryRetry
   event counter name MgmtTuDwnRetry entry-val 1 entry-op ge exit-val 1 exit-op lt
   action 10 counter name "MgmtTuDwnRetry" op set value 0
   action 11 counter name "MgmtTuDwn" op inc value 1
  event manager applet pnp_delete
  event syslog mnemonic "PNP_PROFILE_DELETED"
  event timer watchdog time 60
    action 010 cli command "enable"
    action 020 cli command "show run | i ^pnp profile"
    action 030 set pnp_profile "$_cli_result"
    action 040 string match "*pnp*" "$_cli_result"
    action 050 if $_string_result eq "1"
    action 051  puts " found $_cli_result"
    action 052  break
    action 060 else
    action 061  puts "Did not find any pnp profile. enabling http default"
    action 081  cli command "conf t"
    action 082  cli command "ip http client source-interface Loopback1"
    action 083  cli command "no event manager applet pnp_delete"
    action 084  cli command "do wr"
    action 085  cli command "end"
    action 090 end

<#-- Enable IPv6 -->
  ipv6 access-list Everything-ipv6
   sequence 10 permit ipv6 any any
  !
  class-map type inspect match-any Everything
   match access-group name Everything
   match access-group name Everything-ipv6
  !

end
</#if>
<#else>
  ${provisioningFailed("FAR is not running IOS or IOS-XE")}
</#if>
