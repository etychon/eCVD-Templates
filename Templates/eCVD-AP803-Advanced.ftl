<#-- Default Access point Configuration -->
<#-- version 1.7 -->

<#if far.bootStrap>
    aaa new-model
    aaa authentication login default local
    aaa authorization exec default local
    ! 
    ip domain name cisco.com
    !
    archive
    path flash:
    maximum 3
    ! 
    !
    username ${deviceDefault.apAdminUsername} privilege 15 secret ${deviceDefault.apAdminPassword}
    <#list far.Users as user >
	   username ${user.userName} privilege ${user.userPriv}  secret ${user.userPassword}
    </#list>
    no username Cisco
    do mkdir flash:/managed/data
    bridge irb
    !
    !
    dot11 syslog
    !
    <#if section.wan_wgb?has_content && section.wan_wgb == "true">
    dot11 ssid ${far.wifiSsid}
      vlan 1
      authentication open
      authentication key-management wpa version 2
      mbssid guest-mode
      wpa-psk ascii 0 ${far.wifiPsk}
      !
    dot11 ssid ${far.wgbSsid}
      vlan 50
      authentication open
      authentication key-management wpa version 2
      wpa-psk ascii 0 ${far.wgbPsk}
    !
    interface Dot11Radio0
      no ip address
      no ip route-cache
      no shut
      !
      encryption vlan 1 mode ciphers aes-ccm
      !
      ssid ${far.wifiSsid}
      !
      mbssid
      station-role root
    !
    int dot11 0.50
      encap dot1Q 50 native
      shutdown
      bridge-group 1
      bridge-group 1 subscriber-loop-control
      bridge-group 1 spanning-disabled
      bridge-group 1 block-unknown-source
      no bridge-group 1 source-learning
      no bridge-group 1 unicast-flooding
    !
    interface Dot11Radio0.1
      encapsulation dot1Q 1
      no ip route-cache
      bridge-group 10
      bridge-group 10 subscriber-loop-control
      bridge-group 10 spanning-disabled
      bridge-group 10 block-unknown-source
      no bridge-group 10 source-learning
      no bridge-group 10 unicast-flooding
    !
    interface Dot11Radio1
     no ip address
     no shut
     encryption vlan 50 mode ciphers aes-ccm
     encryption mode ciphers aes-ccm
     ssid ${far.wgbSsid}
     antenna gain 0
     no peakdetect
     station-role workgroup-bridge universal ${far.interfaces("Vlan1")[0].macAddress}
    !
    interface Dot11Radio1.50
      encapsulation dot1Q 50 native
      bridge-group 1
      bridge-group 1 spanning-disabled
    !
    interface BVI1
      no ip address
    !
    workgroup-bridge service-vlan 20
    !
    interface GigabitEthernet0.20
      encapsulation dot1Q 20
      ip address dhcp
    !
    interface GigabitEthernet0.50
      encapsulation dot1Q 50 native
      bridge-group 1
      bridge-group 1 spanning-disabled
    !
    interface GigabitEthernet0.1
      encapsulation dot1Q 1
      no ip route-cache
      bridge-group 10
      bridge-group 10 spanning-disabled
      no bridge-group 10 source-learning
    !
<#-- This will be triggered if only Hotspot is enabled-->
   <#else>
interface BVI1
      description Cisco Rainier AP v2.21, ${deviceDefault.apIpAddress} should match DHCP
      ip address dhcp
    !

      dot11 ssid ${far.wifiSsid}
        vlan 1
        authentication open
        authentication key-management wpa version 2
        mbssid guest-mode
        wpa-psk ascii 0 ${far.wifiPsk}
      !
      !
      interface Dot11Radio0
        no ip address
        no ip route-cache
        no shut
        !
        encryption vlan 1 mode ciphers aes-ccm
        !
        ssid ${far.wifiSsid}
        !
        no dfs band block
        mbssid
        packet retries 64 drop-packet
        channel dfs
        station-role root
      !
      interface Dot11Radio0.20
        encapsulation dot1Q 20 native
        no ip route-cache
      !
      interface Dot11Radio0.1
        encapsulation dot1Q 1
        bridge-group 10
        no ip route-cache
      !
      interface Dot11Radio1
        no ip address
        no ip route-cache
        no shut
        !
        encryption vlan 1 mode ciphers aes-ccm
        !
        ssid ${far.wifiSsid}
        !
        no dfs band block
        mbssid
        packet retries 64 drop-packet
        channel dfs
        station-role root
      !
      interface Dot11Radio1.20
        encapsulation dot1Q 20 native
        no ip route-cache
      !
      interface Dot11Radio1.1
        encapsulation dot1Q 1
        bridge-group 10
        no ip route-cache
 interface GigabitEthernet0.20
      encapsulation dot1Q 20 native
      no ip route-cache
    !
    !
    interface GigabitEthernet0.1
      encapsulation dot1Q 1 
      no ip route-cache
      bridge-group 10
      bridge-group 10 spanning-disabled

    interface GigabitEthernet0
      description the embedded AP GigabitEthernet 0 is an internal interface connecting AP with the host router
      no ip address
      no ip route-cache
    </#if>
    
    bridge 1 aging-time 86400
    bridge 10 aging-time 86400
    !
    !
    ip http server
    ip http authentication local
    ip http secure-server
    ip http secure-port 8443
    !ip http secure-trustpoint LDevID
    !
    wsma agent exec
    profile exec
    !
    wsma agent config
    profile config
    !
    wsma agent filesys
    profile filesys
    !
    wsma profile listener exec
    transport https path /wsma/exec
    !
    wsma profile listener config
    transport https path /wsma/config
    !
    wsma profile listener filesys
    transport https path /wsma/filesys
    !
    no banner exec
    !
    no banner login
    !

<#else>

</#if>
