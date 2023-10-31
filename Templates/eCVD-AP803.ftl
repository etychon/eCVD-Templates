<#-- Default Access point Configuration -->
<#-- eCVD AP803 ADVANCED template -->
<#-- version 1.82 -->

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
    no enable secret
    !
    username ${deviceDefault.apAdminUsername} privilege 15 secret ${deviceDefault.apAdminPassword}
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
    dot11 ssid ${far.wgbSSID}
      vlan 50
      authentication open
      authentication key-management wpa version 2
      wpa-psk ascii 0 ${far.wgbPSK}
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
    interface Dot11Radio0.50
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
     ssid ${far.wgbSSID}
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
        description Cisco IoT OD eCVD Advanced AP, no WGB, ${deviceDefault.apIpAddress} should match DHCP
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
    line con 0
      length 0
    !
    wsma agent exec
      profile exec
      profile execHttp
    !
    wsma agent config
      profile config
      profile configHttp
    !
    wsma agent filesys
      profile filesys
      profile filesysHttp
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
    wsma profile listener execHttp
      transport http path /wsma/exec
    !
    wsma profile listener configHttp
      transport http path /wsma/config
    !
    wsma profile listener filesysHttp
      transport http path /wsma/filesys
    !
    no banner exec
    !
    no banner login
    !

<#else>

</#if>
