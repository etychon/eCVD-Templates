<#-- eCVD AP803 BASIC template -->
<#-- version 1.8 -->

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
      !
      bridge 1 aging-time 86400
      bridge 10 aging-time 86400
!
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
    !
    !
    ip http server
    ip http authentication local
    ip http secure-server
    ip http secure-port 8443
    !ip http secure-trustpoint LDevID
    ip http secure-trustpoint CISCO_IDEVID_SUDI
    ip http client secure-trustpoint CISCO_IDEVID_SUDI
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
    end

<#else>
   !
</#if>
