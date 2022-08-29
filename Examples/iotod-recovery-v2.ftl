<#if section.devicesettings_recovery?has_content && section.devicesettings_recovery == "true">
  <#if !far.recoveryTimer?has_content>
    <#assign recoveryTime = 120>
  <#else>
    <#assign recoveryTime = far.recoveryTimer>
  </#if>
!
service internal
ip sla 51
icmp-echo 1.0.0.1
 frequency 60
ip sla schedule 51 life forever start-time now
track 51 ip sla 51 reachability
track 88 interface Tunnel1 line-protocol
event manager environment outage_total_limit ${recoveryTime}
event manager environment gateway_reboot_time 60
event manager environment modem_reboot_time 30
event manager environment outage_current 0
!
no event manager applet READ_CURRENT_OUTAGE
event manager applet READ_CURRENT_OUTAGE
 description "Read current outage timer value if one exists on flash"
 event timer countdown time 30 maxrun 99
 action 1.0 cli command "enable"
 action 1.2 track read 88
 action 1.4 if $_track_state eq "up"
 action 1.6 cli command "delete /f flash:/current_outage_timer"
 action 1.8 end
 action 2.0 cli command "dir flash:/current_outage_timer"
 action 2.2 regexp "-rw-" "$_cli_result"
 action 2.4 if $_regexp_result eq "0"
 action 2.6 cli command "config t"
 action 2.8 cli command "event manager environment outage_current 0"
 action 3.0 else
 action 3.2 file open fd flash:/current_outage_timer r
 action 3.4 file gets fd value
 action 3.6 cli command "config t"
 action 3.8 cli command "event manager environment outage_current $value"
 action 4.0 end
!
no event manager applet RESET_RECOVERY_COUNTER
event manager applet RESET_RECOVERY_COUNTER
 description "Reset counter when IOTD connectivity is restored."
 event track 88 state up maxrun 99
 action 1.0 cli command "enable"
 action 2.0 syslog msg "Connectivity restored. Clearing GW recovery counter and send periodic update."
 action 2.2 cli command "cgna exec profile cg-nms-periodic"
 action 3.1 cli command "config t"
 action 3.2 cli command "event manager environment outage_current 0"
!
no event manager applet PERFORM_RECOVERY_ACTIONS
event manager applet PERFORM_RECOVERY_ACTIONS
 event timer watchdog time 60 maxrun 99
 action 1.0 cli command "enable"
 action 1.2 track read 88
 action 1.4 if $_track_state eq "down"
 action 1.6 inc outage_current
 action 2.0 comment syslog msg "IOTD Connectivity failure. Outage increased to: $outage_current"
 action 2.2 cli command "config t"
 action 2.4 cli command "event manager environment outage_current $outage_current"
 action 2.6 cli command "end"
 action 2.8 track read 51
 action 3.0 if $_track_state eq "down"
   !
   ! Reload router when no net & OTOD connectivity outage lasts longer than configured router reload time
   !
   action 3.2 divide $outage_current $gateway_reboot_time
   action 3.4 if $_remainder eq 0
     action 3.6 syslog msg "Internet connectivity lost for $outage_current min. Attempting gateway reload"
     action 3.8 file open fd flash:/current_outage_timer w
     action 4.0 file puts fd "$outage_current"
   action 4.2 reload
 action 4.4 end
 !
 ! Reboot modem when no net & IOTOD connectivity outage lasts longer than configured modem reload time
 !
 <#if isFirstCell == "true">
   action 4.6 divide $outage_current $modem_reboot_time
   action 4.8 if $_remainder eq 0
   action 5.0 syslog msg "Internet connectivity lost for $outage_current min. Attempting modem reload"
   action 5.2 cli command "enable"
   action 5.4 cli command "test ${cell_if1} modem-power-cycle" pattern "#"
   action 5.6 end
   action 5.8 end
 </#if>
 !
 ! Perform router recovery from pnp when recovery timer is exceeded
 !
 action 6.0 if $outage_current gt $outage_total_limit
 action 6.1 syslog msg "Recovery timer expired. Initiating GW recovery."
 action 6.2 cli command "enable"
 action 6.3 cli command "show platform nvram | redirect flash:iotd_recovery.log" pattern "confirm|#"
 action 6.4 cli command ""
 action 6.5 cli command "show platform hypervisor | append flash:iotd_recovery.log" pattern "#"
 action 6.6 cli command "show iox host list detail | append flash:iotd_recovery.log" pattern "#"
 action 6.7 cli command "dir /all /recursive all-filesystems | append flash:iotd_recovery.log" pattern "#"
 action 6.8 cli command "show pnp tech-support | append flash:iotd_recovery.log" pattern "#"
 action 6.9 cli command "show clock detail | append flash:iotd_recovery.log" pattern "#"
 action 7.0 cli command "show tech-support | append flash:iotd_recovery.log" pattern "#"
 action 7.1 cli command "show clock detail | append flash:iotd_recovery.log" pattern "#"
 action 7.2 cli command "show logging | append flash:iotd_recovery.log" pattern "#"
 action 7.3 cli command "delete /f flash:express-setup-config*"
 action 7.4 cli command "delete /f flash:before-registration-config*"
 action 7.5 cli command "delete /f flash:before-tunnel-config*"
 action 7.6 cli command "delete /f flash:/-*"
 action 7.7 cli command "delete /f flash:/current_outage_timer"
 action 7.8 cli command "dir flash:/managed/bypass-discovery.cfg"
 action 8.0 regexp "-rw-" "$_cli_result"
 action 8.1 if $_regexp_result eq "0"
 action 8.2 syslog msg "*** bypass-discovery.cfg file NOT found in dir /managed, Performing full pnp ***"
 action 8.3 cli command "erase nvram:" pattern "confirm|#"
 action 8.4 cli command ""
 action 8.5 reload
 action 8.6 else
 action 8.7 syslog msg "*** bypass-discovery.cfg FOUND in flash:/managed, performing reset ***"
 action 8.8 cli command "copy flash:/managed/bypass-discovery.cfg startup-config" pattern "startup-config|#"
 action 9.0 cli command ""
 action 9.1 wait 10
 action 9.2 reload
 action 9.3 end
 action 9.4 end
 action 9.5 end
!
!
</#if>
