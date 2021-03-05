<#-- Default Access point Configuration -->
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
    no username Cisco
    do mkdir flash:/managed/data
    bridge irb
    !
    interface GigabitEthernet0
    encapsulation dot1Q 1 native
    !
    interface BVI1
    description Cisco Rainier AP v2.21, ${deviceDefault.apIpAddress} should match DHCP
    ip address dhcp
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
    end

<#else>

</#if>
