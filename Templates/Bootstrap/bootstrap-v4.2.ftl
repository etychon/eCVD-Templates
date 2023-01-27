<#-- Default BootStrap Configuration -->
<#if far.isRunningIos()>
    <#assign sublist = far.eid?split("+")[0..1]>
    <#assign pid = sublist[0]>
    <#assign model = pid[0..4]>
<#if isRollbackConfig?has_content && isRollbackConfig==true>
    <#-- NOTE: If making custom changes to this template, avoid adding changes in this 'if' block and add changes in the 'else' block below -->
    event manager applet iotodrollback
     event timer countdown time 10 maxrun 99
     action 1 cli command "enable"
    <#if model == "IR829">
        action 2 cli command "service-module wlan-ap 0 reset default-config"
    </#if>
     action 3.1 cli command "delete /f flash:express-setup-config*"
     action 3.2 cli command "delete /f flash:before-registration-config*"
     action 3.3 cli command "delete /f flash:before-tunnel-config*"
     action 3.4 cli command "delete /f flash:/-*"
     action 4 cli command "erase nvram:" pattern "confirm|#"
     action 5 cli command ""
     action 6 reload

<#else>
  <#-- NOTE: If making custom changes to this template, add changes in this 'else' block -->
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
  <#-- Determine Ethernet/Cellular WAN interface based on Model - 807, 809, 829, 1101, 1800 -->
  <#if model == "IR807">
    <#assign ether_if = "FastEthernet0">
    <#assign cell_ifs =  ["Cellular 0"]>
    <#assign cell_contrs =  ["Cellular 0"]>
  <#elseif model == "IR110">
    <#assign model = "IR1101">
    <#assign ether_if = "GigabitEthernet0/0/0">
    <#-- List all cellular interfaces/controllers for modular DUAL LTE router -->
    <#assign cell_ifs =  ["Cellular 0/1/0", "Cellular 0/3/0", "Cellular 0/4/0"]>
    <#assign cell_contrs =  ["Cellular 0/1/0", "Cellular 0/3/0", "Cellular 0/4/0"]>
  <#elseif model == "IR182" || model == "IR183">
    <#if model == "IR182">
      <#assign cell_ifs = ["Cellular 0/4/0"]>
      <#assign cell_contrs = ["Cellular 0/4/0"]>
    <#else>
      <#assign cell_ifs = ["Cellular 0/4/0", "Cellular 0/5/0"]>
      <#assign cell_contrs = ["Cellular 0/4/0", "Cellular 0/5/0"]>
    </#if>
    <#assign ether_if = "GigabitEthernet0/0/0">
    <#assign model = "IR1800">
  <#else>
    <#if model == "IR829" && ir829_use_gi1>
      <#assign ether_if = "Vlan 10">
    <#else>
      <#assign ether_if = "GigabitEthernet0">
    </#if>
    <#assign cell_ifs = ["Cellular 0"]>
    <#assign cell_contrs = ["Cellular 0"]>
    <#if pid?contains("2LTE")>
      <#assign cell_ifs = ["Cellular 0/0"]>
      <#if (far.cellularICCID3!?length == 19 || far.cellularICCID3!?length == 20) && !(far.cellularICCID1!?length == 19 || far.cellularICCID1!?length == 20)>
        <#assign cell_ifs = ["Cellular 1/0"]>
        <#assign cell_contrs = ["Cellular 1"]>
      </#if>
      <#--  TODO validate dual lte on IR829-2LTE before eenabling-->
      <#--  <#assign cell_ifs = ["Cellular 0/0", "Cellular 1/0"]>-->
      <#--  <#assign cell_contrs = ["Cellular 0", "Cellular 1"]>-->
    </#if>
  </#if>

<#--Adding retry delays for PnP work response so that work response does not get missed if modem is reset -->
  do-exec pnp service internal 1
  do-exec pnp service wait-time 10 20 20
  do-exec pnp service internal 0

  hostname ${model}_${sn}
  alias exec cfgdiff show archive config differences nvram:startup-config system:running-config
  !
  line con 0
  length 0
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
  integrity sha512 sha384 sha256 sha1
  group 19 14 21
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
  description "Cisco IoT Gateway v4.2"
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
  access-list 1 permit any
  !
  ip access-list standard GWIPS
  permit ${nwk_addr} 0.0.0.31
  !
  dialer watch-list 1 ip 5.6.7.8 0.0.0.0
  dialer watch-list 1 delay route-check initial 60
  dialer watch-list 1 delay connect 1
  dialer-list 1 protocol ip permit
  dialer-list 1 protocol ipv6 permit
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
  no shutdown
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
  add-command show interfaces | format flash:/managed/odm/cg-nms.odm
  add-command show hosts | format flash:/managed/odm/cg-nms.odm
  add-command show ipv6 dhcp | format flash:/managed/odm/cg-nms.odm
  add-command show ipv6 interface | format flash:/managed/odm/cg-nms.odm
  add-command show snmp mib ifmib ifindex | format flash:/managed/odm/cg-nms.odm
  <#if model == "IR807" || model == "IR809" || model == "IR829">
    <#if model == "IR809" || model == "IR829">
      add-command show platform hypervisor | format flash:/managed/odm/cg-nms.odm
      add-command show iox host list detail | format flash:/managed/odm/cg-nms.odm
    </#if>
    <#if pid?contains("2LTE")>
      add-command show cellular 0/0 all | format flash:/managed/odm/cg-nms.odm
      add-command show cellular 1/0 all | format flash:/managed/odm/cg-nms.odm
    <#else>
      add-command show cellular 0 all | format flash:/managed/odm/cg-nms.odm
    </#if>
  <#elseif model == "IR1101" || model == "IR1800">
    add-command show iox-service | format flash:/managed/odm/cg-nms.odm
    <#if model == "IR1101">
      <#-- okay if cellular module not plugged in during execution of below cmds -->
      add-command show cellular 0/1/0 all | format flash:/managed/odm/cg-nms.odm
      add-command show cellular 0/3/0 all | format flash:/managed/odm/cg-nms.odm
      add-command show cellular 0/4/0 all | format flash:/managed/odm/cg-nms.odm
    <#elseif model == "IR1800">
      <#-- okay if cellular module not plugged in during execution of below cmds -->
      add-command show cellular 0/4/0 all | format flash:/managed/odm/cg-nms.odm
      add-command show cellular 0/5/0 all | format flash:/managed/odm/cg-nms.odm
    </#if>
  </#if>

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
  ip host ios.local ${gos_if_addr}
  ip access-list extended NAT_ACL
    permit ip ${iox_subnet} 0.0.0.7 any
  !
  ip dhcp pool ioxpool
 	  network ${iox_subnet} 255.255.255.248
 	  default-router ${gos_if_addr}
  	  dns-server ${gos_if_addr} 8.8.8.8
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

<#if model == "IR1101" || model == "IR1800" >

  ip ssh server algorithm mac hmac-sha2-256 hmac-sha2-512 hmac-sha2-256-etm@openssh.com hmac-sha2-512-etm@openssh.com
  
  <#-- This block only to be used for devices that have been validated for dual LTE capability-->
  <#-- find active cell interface. If more than one is active then only pick first one-->
  <#assign active_cell_if_primary =  "">
  <#assign active_cell_ifs =  []>
  <#assign all_present_cell_ifs =  []>
  <#if deviceDefault.interfaces("cell", "0")?has_content>
    <#list deviceDefault.interfaces("cell", "0") as interface>
      <#list interface as propName, propValue>
        <#if propValue?has_content && propValue?is_string>
          <#if propName == "cellularStatus" && propValue == "Active">
            <#if active_cell_if_primary?has_content == false>
              <#assign active_cell_if_primary = interface.name?replace("Cellular", "Cellular ")>
              ! active_cell_if_primary = ${active_cell_if_primary}
            </#if>
            <#assign active_cell_ifs += [interface.name?replace("Cellular", "Cellular ")]>
          </#if>
        </#if>
      </#list>
      <#assign all_present_cell_ifs += [interface.name?replace("Cellular", "Cellular ")]>
    </#list>
  </#if>

  <#if active_cell_if_primary?has_content>
    <#assign active_cell_contr = active_cell_if_primary>
    <#if pid?contains("2LTE")>
      <#assign active_cell_contr = active_cell_if_primary?replace("/[0-9]", "", "r")>
    </#if>
    <#assign cell_ifs = [active_cell_if_primary] + cell_ifs>
    <#assign cell_contrs = [active_cell_contr] + cell_contrs>
  </#if>

  <#assign cell_default_weights =  ["95", "97"]>
  <#assign cell_her_weights =  ["90", "92"]>
  <#assign alreadyProcessed = []>
  <#assign duplicatedEntry = []>
  <#list cell_ifs as cell_if>
    <#if alreadyProcessed?seq_contains(cell_if)>
      <#assign duplicatedEntry += [cell_if]>
      <#continue>
    </#if>
    <#assign i = cell_if?index>
    <#-- Initialize weghts for primary ("Cellular 0/0" [IR829-2LTE], "Cellular 0/1/0" [IR1101], "Cellular 0/4/0" [IR1800]) and secondary cell interfaces ("Cellular 1/0" [IR829-2LTE], "Cellular 0/3/0" [IR1100], "Cellular 0/4/0" [IR1100], "Cellular0/5/0" [IR1800]) -->
    <#assign k = i - duplicatedEntry?size>
    <#assign j = k>
    <#if i gt 0>
      <#assign j = 1>
    </#if>
    <#if cell_if == "Cellular 0/1/0" || cell_if == "Cellular 0/0" || (cell_if == "Cellular 0/4/0" && model == "IR1800")>
      event man env primaryCellIfHerWeight ${cell_her_weights[j]}
      event man env primaryCellIfDefaultWeight ${cell_default_weights[j]}
    <#elseif k lt cell_her_weights?size>
      event man env secondCellIfHerWeight ${cell_her_weights[j]}
      event man env secondCellIfDefaultWeight ${cell_default_weights[j]}
    </#if>
    <#assign appletName = "cell_pnp_${cell_if?replace(' ', '')}">
    event manager applet ${appletName}
    <#if all_present_cell_ifs?seq_contains(cell_if)>
      <#--  For present cell interface set timer to 20. For secondary set to 25 -->
      event timer watchdog time ${20 + j * 5}
    <#else>
      event none
    </#if>
    action 100 cli command "enable"
    action 105 cli command "conf t"
    action 110 cli command "controller ${cell_contrs[i]}"
    action 115 regexp "Invalid input detected" $_cli_result match reg_match_found
    action 120 if $_regexp_result eq 1
      action 125 syslog msg  "Controller ${cell_contrs[i]} not found at the moment."
    action 150 else
      action 160 cli command  "src-ip-violation-action drop ipv4"
      !
      !
      action 310 cli command "int ${cell_if}"
      action 311 cli command "ip address negotiated"
      <#--  action 314 cli command "ip access-group 1 out"-->
      action 315 cli command "dialer in-band"
      action 316 cli command "dialer idle-timeout 0"
      action 317 cli command "dialer-group 1"
      action 318 cli command "dialer watch-group 1"
      action 320 cli command "ipv6 enable"
      action 321 cli command "zone-member security INTERNET"
      <#if model == "IR1101" || model == "IR1800">
        action 322 cli command "pulse-time 1"
        action 324 cli command "ip tcp adjust-mss 1460"
      </#if>
      action 325 cli command "no shutdown"

      <#if cell_if == "Cellular 0/1/0" || cell_if == "Cellular 0/0" || (cell_if == "Cellular 0/4/0" && model == "IR1800")>
        action 330 cli command  "ip route 0.0.0.0 0.0.0.0 ${cell_if} $primaryCellIfDefaultWeight"
        action 340 cli command  "ip route $herip 255.255.255.255 ${cell_if} $primaryCellIfHerWeight"
        action 345 cli command  "track 2 interface ${cell_if} ip routing"
        action 355 cli command  "source 2 ${cell_if} track 2"
      <#else>
        action 330 cli command  "ip route 0.0.0.0 0.0.0.0 ${cell_if} $secondCellIfDefaultWeight"
        action 340 cli command  "ip route $herip 255.255.255.255 ${cell_if} $secondCellIfHerWeight"
        action 345 cli command  "track 3 interface ${cell_if} ip routing"
        action 355 cli command  "source 3 ${cell_if} track 3"
      </#if>
      <#--  Line below should be before "source x cell_if track x" cmd above-->
      action 350 cli command  "crypto ikev2 client flexvpn Tunnel1"
    action 370 end

    <#if model == "IR1101" || model == "IR1800">
      <#-- Keep applet saved for devices with pluggable cellular modules. To be triggered via SYSLOG event when cell module plugged in or during device reboot -->
      action 400 cli command "event manager applet ${appletName}"
      action 410 cli command "event none"
      action 420 syslog msg "Successfully ran ${appletName} applet. Removing event timer."
    <#else>
      action 430 syslog msg "Deleting ${appletName} applet. No longer needed."
      action 440 cli command "no event manager applet ${appletName}"
    </#if>
    action 500 cli command "end"
    <#assign alreadyProcessed += [cell_if]>
  </#list>

  event manager applet pnp_save_config
  event timer watchdog time 30
  action 1 cli command "enable"
  action 2 cli command "conf t"
  action 3 cli command "do wr"
  action 4 cli command "do del /f flash:/before-registration-config*"
  action 5 cli command "do del /f flash:/express-setup-config*"
  action 6 syslog msg "Deleting pnp_save_config applet. No longer needed."
  action 7 cli command "no event manager applet pnp_save_config"
  action 8 cli command "end"
<#else>
  <#--  This block is for non IoTOD supported/validated dual LTE devices -->
  event manager applet cell_pnp
  event timer watchdog time 20
  action 1 cli command "enable"
  action 2 cli command "conf t"
  action 2.1 cli command "controller ${cell_contrs[0]}"
  action 2.2 cli command "src-ip-violation-action drop ipv4"
  action 2.3 cli command "int ${cell_ifs[0]}"
  action 2.4 cli command "dialer in-band"
  action 2.5 cli command "dialer-group 1"
  action 2.55 cli command "dialer watch-group 1"
  action 2.6 cli command "zone-member security INTERNET"
  action 3 cli command "ip route 0.0.0.0 0.0.0.0 ${cell_ifs[0]} 100"
  action 3.1 cli command "ip route ${herip} 255.255.255.255 ${cell_ifs[0]} 10"
  action 4 cli command "track 2 interface ${cell_ifs[0]} ip routing"
  action 5 cli command "crypto ikev2 client flexvpn Tunnel1"
  action 6 cli command "source 2 ${cell_ifs[0]} track 2"
  action 7 cli command "no event manager applet cell_pnp"
  action 8 cli command "do wr"
  action 9.1 cli command "do del /f flash:/before-registration-config"
  action 9.2 cli command "do del /f flash:/express-setup-config"
</#if>

<#if model == "IR1101" || model == "IR1800">
  event manager applet cell_module_detected
    event syslog mnemonic "INSSPA"
    action 010   regexp "(SPA inserted in subslot ([0-9\/]+))" "$_syslog_msg" match reg_match_1
    action 020   if $_regexp_result eq 1
    action 030     regexp "([0-9\/]+)" "$reg_match_1" match subslot
    action 040     if $_regexp_result eq 1
   !action 050       syslog msg "Identified module was plugged into subslot $subslot"
    action 055       set cellIntfSuffix "$subslot/0"
    action 060       set cellPnpAppletName "cell_pnp_Cellular$cellIntfSuffix"
    action 070       set gpsEnableAppletName "GPS_ENABLE_${model}_Cellular$cellIntfSuffix"
    action 080       cli command "enable"
    <#-- Check for cell_pnp applet -->
   !action 090       syslog msg "Checking if applet $cellPnpAppletName exists"
    action 100       cli command "show run | inc ^event manager applet $cellPnpAppletName"
    action 110       string match "*event manager applet cell_pnp_Cellular*" "$_cli_result"
    action 120       if $_string_result eq "1"
    action 140         syslog msg "Enabling cell applet $cellPnpAppletName with 20 sec timer"
    action 150         cli command "conf t"
    action 160         cli command "event manager applet $cellPnpAppletName"
    action 170         cli command "event timer watchdog time 20"
    action 180         cli command "end"
    action 190       else
   !action 200         syslog msg "$cellPnpAppletName applet not found"
    action 210       end
    <#-- Check for GPS applet -->
   !action 220       syslog msg "Checking if applet $gpsEnableAppletName exists"
    action 230       cli command "show run | inc ^event manager applet $gpsEnableAppletName"
    action 240       string match "*event manager applet GPS_ENABLE_${model}*" "$_cli_result"
    action 250       if $_string_result eq "1"
    action 270         syslog msg "Enabling cell applet $gpsEnableAppletName with 60 sec timer"
    action 280         cli command "conf t"
    action 290         cli command "event manager applet $gpsEnableAppletName"
    action 300         cli command "event timer watchdog time 60"
    action 310         cli command "end"
    action 320       else
   !action 330         syslog msg "$gpsEnableAppletName applet not found"
    action 340       end
    action 350     end
    action 360   end

  <#-- GPS Enable applet below -->
  <#assign alreadyProcessed = []>
  <#list cell_ifs as cell_if>
    <#if alreadyProcessed?seq_contains(cell_if)>
      <#continue>
    </#if>
    <#assign i = cell_if?index>
    event manager applet GPS_ENABLE_${model}_${cell_if?replace(' ', '')}
    <#if all_present_cell_ifs?seq_contains(cell_if)>
      <#-- Create GPS applet for all potential modem subslots -->
      <#-- Enable timer only for present interfaces -->
       event timer watchdog time 90
    <#else>
        event none
    </#if>
    action 010 cli command "enable"
    action 020 cli command "show ${cell_if} firmware"
   !action 025 puts "_cli_result = '$_cli_result'\n"
    action 030 regexp "Firmware Activation mode" $_cli_result match
    action 040 if $_regexp_result ne "1"
        action 041 string match "*Invalid input detected*" "$_cli_result"
        action 042 cli command "conf t"
        action 043 cli command "event manager applet GPS_ENABLE_${model}_${cell_if?replace(' ', '')}"
        action 044 if $_string_result eq 1
            action 047 syslog msg "${cell_if} interface not found. Removing event timer"
            action 048 cli command "event none"
        action 050 else
            action 053 syslog msg "Modem is DOWN, not touching anything and exiting"
            <#-- Allow modem 10 min to come up -->
            action 054 cli command "event timer watchdog time 600"
        action 055 end
        action 060 exit
    action 070 end
    action 080 cli command "show ${cell_if} hardware | inc Modem Firmware Version"
    action 090 regexp "^Modem Firmware Version =[ ]+SWI(.+)$" $_cli_result match _modem_version
    action 092 cli command "conf t"
    action 095 if $_regexp_result eq 1
        action 100 puts "Found supported modem with version $_modem_version"
        action 200 cli command "do show ${cell_if} gps"
        action 201 foreach line $_cli_result "\r\n"
           !action 203 syslog msg  "PROCESSING LINE '$line'"
            action 205 regexp "^GPS Mode Configured =[ ]+(.+)$" $line match _gps_mode
            action 210 if $_regexp_result eq 1
               !action 212 syslog msg  "GPS MODE $_gps_mode"
                action 215 if $_gps_mode eq "not configured"
                    action 220 syslog msg  "Enabling GPS standalone mode"
                    action 230 cli command "controller ${cell_contrs[i]}"
                    action 240 cli command "lte gps auto-reset"
                    action 250 cli command "lte gps mode standalone"
                    action 260 cli command "lte gps nmea"
                    action 270 cli command "service internal"
                    action 280 cli command "do test ${cell_if} modem-power-cycle"
                    action 282 break
                action 285 end
                action 290 if $_gps_mode eq "Modem reset/power-cycle is needed to change GPS Mode to not configured"
                    action 295 syslog msg  "LTE module being power-cycled"
                    action 305 cli command "service internal"
                    action 310 cli command "do test ${cell_if} modem-power-cycle"
                    action 315 break
                action 320 end
            action 370 end
            action 405 regexp "^GPS Status =[ ]+(.+)$" $line match _gps_status
            action 410 if $_regexp_result eq 1
                action 415 syslog msg "GPS STATUS '$_gps_status'"
                action 420 if $_gps_status eq "NMEA Disabled"
                    action 425 syslog msg "Configuring NMEA mode on GPS"
                    action 430 cli command "controller ${cell_if}"
                    action 440 cli command "lte gps nmea"
                    action 445 break
                action 450 end
            action 455 end
        action 460 end
    action 500 else
        action 510 syslog msg "Not a Sierra Wireless modem"
    action 600 end
   !action 620 syslog msg "Removing GPS applet event timer"
    action 630 cli command "event manager applet GPS_ENABLE_${model}_${cell_if?replace(' ', '')}"
    action 640 cli command "event none"
    action 650 cli command "end"
    <#assign alreadyProcessed += [cell_if]>
  </#list>
</#if>

  event manager applet updateSNMP
  <#-- Keeping event timer below 5 min reduces likeliness of device being marked as 'DOWN' if mark down timer is set to minimum option of 5 min in OD -->
  event timer watchdog time 150
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
   event tag 1 track 111 state down maxrun 330 ratelimit 5
   event tag 2 counter name MgmtTuDwn entry-val 1 entry-op ge exit-val 1 exit-op ge
   event tag 3 timer cron cron-entry "@reboot"
   event tag 4 none
   trigger
    correlate event 1 or event 2 or event 3 or event 4
  !action  005  syslog msg "MgmtTuRecvry EEM applet has been triggered by event type - $_event_type_string"
   action  010  track read 111
   action  020  if $_track_state eq "up"
   action  030    counter name "MgmtTuDwn" op set value 0
   action  040    exit
   action  050  end
   action  060  cli command "enable"
   action  070  cli command "ping 8.8.8.8 rep 1 time 0"
   action  080  cli command "conf t"
   action  090  cli command "crypto ikev2 client flexvpn Tunnel1"
   action  100  cli command "peer 1 fqdn ${her_name}"
   action  110  regexp "resolved to address: ([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\r" "$_cli_result" match newip
   action  120  if $_regexp_result eq "1"
   action  130    if $newip ne "$herip"
  !action  140      syslog msg "TUNNEL1 new headend IP. Updating existing Tunnel1 peer address and interfaces' routes from $herip IP to $newip"
   action  150      cli command "crypto ikev2 keyring Flex_key"
   action  160      cli command "peer cloud-core-router"
   action  170      cli command "address $newip"
   action  180      cli command "ip route $newip 255.255.255.255 ${ether_if} dhcp"
   action  190      cli command "no ip route $herip 255.255.255.255 ${ether_if} dhcp"
   <#if model == "IR1101" || model == "IR1800">
     <#assign alreadyProcessed = []>
     <#list cell_ifs as cell_if>
       <#if alreadyProcessed?seq_contains(cell_if)>
         <#continue>
       </#if>
       <#assign i = cell_if?index>
       <#-- okay if cellular interface not present for modular device at a given time of applet execution -->
       <#if cell_if == "Cellular 0/1/0" || cell_if == "Cellular 0/0" || (cell_if == "Cellular 0/4/0" && model == "IR1800")>
         action 20${i}  cli command "ip route $newip 255.255.255.255 ${cell_if} $primaryCellIfHerWeight"
       <#else>
         action 20${i}  cli command "ip route $newip 255.255.255.255 ${cell_if} $secondCellIfHerWeight"
       </#if>
       action  21${i}   cli command "no ip route $herip 255.255.255.255 ${cell_if}"
       <#assign alreadyProcessed += [cell_if]>
     </#list>
   <#else>
     action  200        cli command "ip route $newip 255.255.255.255 ${cell_ifs[0]} 10"
     action  210        cli command "no ip route $herip 255.255.255.255 ${cell_ifs[0]} 10"
   </#if>
   action  300          cli command "event man env herip $newip"
   action  310          cli command "do wr"
   action  320    end
   action  330  end
    <#if model == "IR1101" || (model == "IR1800" && pid?contains("IR1821") == false)>
     <#-- For devices that support dual LTE, update cell interface priorities here via EEM -->
     action  340   wait 4
     action  350   cli command "do show crypto ikev2 client flexvpn Tunnel1 | inc Current state:ACTIVE$"
     action  360   string match "*Current state:ACTIVE*" "$_cli_result"
     action  370   if $_string_result eq "0"
    !action  380     syslog msg "Management VPN inactive. Clearing NAT translations and crypto sa"
     action  390     cli command "do event manager run MgmtTuRecvry"
     action  400     cli command "do clear ip nat translation *"
     action  410     cli command "do clear crypto sa map Tunnel1-head-0"
     action  420     cli command "do event manager run updateRoutesDualLte"
     action  430   end
    </#if>
   action  500  wait 300
   action  510  counter name "MgmtTuDwnRetry" op inc value 1

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

<#if model == "IR1101" || model == "IR1800">
  event manager applet checkManagementVpnActive
    event timer watchdog name checkManagementVpnActive time 300
    action 010  cli command "enable"
    action 020  cli command "show crypto ikev2 client flexvpn Tunnel1 | inc Current state:ACTIVE$"
    action 030  string match "*Current state:ACTIVE*" "$_cli_result"
    action 040  if $_string_result eq "0"
   !action 050    syslog msg "Management VPN inactive. Clearing NAT translations and crypto sa"
    action 070    cli command "clear ip nat translation *"
    action 080    cli command "clear crypto sa map Tunnel1-head-0"
    <#if pid?contains("IR1821") == false>
      action 090  cli command "event manager run MgmtTuRecvry"
    </#if>
    action 100  end

  <#if pid?contains("IR1821") == false>
    event manager applet managementVpnConnectionDown
      event syslog mnemonic "FLEXVPN_CONNECTION_DOWN" ratelimit 5
      <#-- Tunnel1 is always the OD Management tunnel -->
      action 020    regexp "FlexVPN\(Tunnel1\)" "$_syslog_msg"
      action 030    if $_regexp_result ne 1
      action 040      exit
      action 050    end
      action 060    cli command "enable"
      action 070    cli command "event manager run MgmtTuRecvry"

    event manager applet updateRoutesDualLte
      event none
      action 010  cli command "enable"
      action 020  set interfacesPrioritizedStrList ""
      action 030  cli command "sh ip int brief | inc ^Cellular([0-9\/]+)0.*.([0-9]*\.[0-9]*\.[0-9]*\.[0-9]*).*up.*up.*$"
      action 040  foreach line $_cli_result "\r\n"
      action 050    set _cell_intf ""
      action 060    regexp "Cellular....." $line _cell_intf
      action 070    if $_cell_intf eq ""
      action 080      continue
      action 090    end
      action 100    set interfacesPrioritizedStrList "$interfacesPrioritizedStrList\r\n$_cell_intf"
      action 110  end
      action 130  cli command "sh ip int brief | inc ^Cellular([0-9\/]+)0.*$"
      action 150  foreach line $_cli_result "\r\n"
      action 160    set _cell_intf ""
      action 170    regexp "Cellular....." $line _cell_intf
      action 180    if $_cell_intf eq ""
      action 190      continue
      action 200    end
      action 210    set _if_found ""
      action 230    string first "$_cell_intf" "$interfacesPrioritizedStrList"
      action 240    if $_string_result gt "-1"
      action 260      continue
      action 270    end
      action 290    set interfacesPrioritizedStrList "$interfacesPrioritizedStrList\r\n$_cell_intf"
      action 300  end
     !action 310  syslog msg "interfacesPrioritizedStrList => '$interfacesPrioritizedStrList'"
      action 320  if $interfacesPrioritizedStrList eq "0"
      action 330    exit
      action 340  end
      action 360  set maxCellIfDefaultWeight ""
      action 365  set minCellIfDefaultWeight ""
      action 370  set maxCellIfHerWeight ""
      action 375  set minCellIfHerWeight ""
      action 380  if "$primaryCellIfDefaultWeight" eq "$secondCellIfDefaultWeight"
      action 385    set minCellIfDefaultWeight "${cell_default_weights[0]}"
      action 390    set maxCellIfDefaultWeight "${cell_default_weights[1]}"
      action 400  elseif "$primaryCellIfDefaultWeight" lt "$secondCellIfDefaultWeight"
      action 405    set maxCellIfDefaultWeight "$secondCellIfDefaultWeight"
      action 410    set minCellIfDefaultWeight "$primaryCellIfDefaultWeight"
      action 420  else
      action 425    set maxCellIfDefaultWeight "$primaryCellIfDefaultWeight"
      action 430    set minCellIfDefaultWeight "$secondCellIfDefaultWeight"
      action 440  end
      action 445  if "$primaryCellIfHerWeight" eq "$secondCellIfHerWeight"
      action 450    set minCellIfHerWeight "${cell_her_weights[0]}"
      action 455    set maxCellIfHerWeight "${cell_her_weights[1]}"
      action 475  elseif "$primaryCellIfHerWeight" lt "$secondCellIfHerWeight"
      action 480    set maxCellIfHerWeight "$secondCellIfHerWeight"
      action 485    set minCellIfHerWeight "$primaryCellIfHerWeight"
      action 495  else
      action 500    set maxCellIfHerWeight "$primaryCellIfHerWeight"
      action 505    set minCellIfHerWeight "$secondCellIfHerWeight"
      action 515  end
      action 520  cli command  "conf t"
      action 522  set cellHerMinWeightAlreadyUsed "false"
      action 525  set cellHerMaxWeightAlreadyUsed "false"
      action 527  set setPrimaryInterfaceFound "false"
      action 530  foreach interface $interfacesPrioritizedStrList "\r\n"
      action 535    if $interface eq ""
      action 540      continue
      action 545    end
      action 560    set currCellDefaultWeight ""
      action 565    set currCellHerWeight ""
      action 570    if $cellHerMinWeightAlreadyUsed eq "false"
      action 575      set currCellDefaultWeight "$minCellIfDefaultWeight"
      action 580      set currCellHerWeight "$minCellIfHerWeight"
      action 585      set cellHerMinWeightAlreadyUsed "true"
      action 590    else
      action 600      set currCellDefaultWeight "$maxCellIfDefaultWeight"
      action 610      set currCellHerWeight "$maxCellIfHerWeight"
      action 615      set cellHerMaxWeightAlreadyUsed "true"
      action 620    end
     !action 630    syslog msg "For interface '$interface' using herip ($herip) weight '$currCellHerWeight' and default gateway weight '$currCellDefaultWeight'"
      action 640    cli command  "ip route 0.0.0.0 0.0.0.0 $interface $currCellDefaultWeight"
      action 650    cli command  "ip route $herip 255.255.255.255 $interface $currCellHerWeight"
      <#if model == "IR1101">
        action 660  if "$interface" eq "Cellular0/1/0"
        action 670    cli command  "event man env primaryCellIfHerWeight $currCellHerWeight"
        action 680    cli command  "event man env primaryCellIfDefaultWeight $currCellDefaultWeight"
        action 690    set setPrimaryInterfaceFound "true"
      <#elseif model == "IR1800">
        action 660  if "$interface" eq "Cellular0/4/0"
        action 670    cli command  "event man env primaryCellIfHerWeight $currCellHerWeight"
        action 680    cli command  "event man env primaryCellIfDefaultWeight $currCellDefaultWeight"
        action 690    set setPrimaryInterfaceFound "true"
      <#else>
        action 660  if "$interface" eq "Cellular0/0"
        action 670    cli command  "event man env primaryCellIfHerWeight $currCellHerWeight"
        action 680    cli command  "event man env primaryCellIfDefaultWeight $currCellDefaultWeight"
        action 690    set setPrimaryInterfaceFound "true"
      </#if>
      action 695    else
      action 700      cli command  "event man env secondCellIfHerWeight $currCellHerWeight"
      action 705      cli command  "event man env secondCellIfDefaultWeight $currCellDefaultWeight"
      action 710    end
      action 715  end
      action 720  if "$cellHerMinWeightAlreadyUsed" ne "$cellHerMaxWeightAlreadyUsed"
      action 725    if "$setPrimaryInterfaceFound" eq "true"
     !action 728      syslog msg  "Updating secondCellIf env variables with max weights"
      action 730      cli command  "event man env secondCellIfHerWeight $maxCellIfHerWeight"
      action 735      cli command  "event man env secondCellIfDefaultWeight $maxCellIfDefaultWeight"
      action 740    else
     !action 742      syslog msg  "Updating primaryCellIf env variables with max weights"
      action 745      cli command  "event man env primaryCellIfHerWeight $maxCellIfHerWeight"
      action 750      cli command  "event man env primaryCellIfDefaultWeight $maxCellIfDefaultWeight"
      action 755    end
      action 760  end
  </#if>
</#if>
end
</#if>
<#else>
  ${provisioningFailed("FAR is not running IOS or IOS-XE")}
</#if>
