!
<#if section.devicesettings_recovery?has_content && section.devicesettings_recovery == "true">
  <#if !far.recoveryTimer?has_content>
    <#assign recoveryTime = 120>
  <#else>
    <#assign recoveryTime = far.recoveryTimer>
  </#if>
!
service internal
no ip sla 51
ip sla 51
 icmp-echo 1.0.0.1
  frequency 30
! sla scheduling will happen only during outage to save on cell data
! ip sla schedule 51 life forever start-time now
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
  event timer countdown time 60 maxrun 99
  action 1.0  cli command "enable"
  action 1.2  cli command "config t"
  action 1.4  track read 88
  action 1.6  if $_track_state eq "up"
  action 1.8    cli command "do-exec delete /f flash:/current_outage_timer"
  action 2.0    cli command "no ip sla schedule 51"
  action 2.2  else
  action 2.4    cli command "ip sla schedule 51 life forever start-time now"
  action 2.6  end
  action 2.8  cli command "do-exec dir flash:/current_outage_timer"
  action 3.0  regexp "-rw-" "$_cli_result"
  action 3.2  if $_regexp_result eq "0"
  action 3.4    cli command "event manager environment outage_current 0"
  action 3.6  else
  action 3.8    file open fd flash:/current_outage_timer r
  action 4.0    file gets fd value
  action 4.2    cli command "event manager environment outage_current $value"
  action 4.4  end
!
no event manager applet RESET_OUTAGE_COUNTER
event manager applet RESET_OUTAGE_COUNTER
  description "Reset counter when IOTD connectivity is restored."
  event track 88 state any maxrun 99
  action 1.0  cli command "enable"
  action 1.2  cli command "config t"
  action 1.4  track read 88
  action 1.6  if $_track_state eq "up"
  action 2.0    syslog msg "Connectivity restored. Clearing GW recovery counter."
                ! force metric update to IOTOD when connection is recovered
  action 2.2    cli command "do-exec cgna exec profile cg-nms-periodic"
  action 2.4    cli command "do-exec delete /f flash:/current_outage_timer"
  action 2.6    cli command "event manager environment outage_current 0"
  action 2.8    cli command "no ip sla schedule 51"
  action 3.0  else
  action 3.2    cli command "ip sla schedule 51 life forever start-time now"
  action 3.4  end
!
no event manager applet PERFORM_OUTAGE_ACTIONS
event manager applet PERFORM_OUTAGE_ACTIONS
  event timer watchdog time 60 maxrun 99
  action 1.0  cli command "enable"
  action 1.2  track read 88
  action 1.4  if $_track_state eq "down"
  action 1.6    inc outage_current
  action 2.0    comment syslog msg "IOTD Connectivity failure. Outage increased to: $outage_current"
  action 2.2    cli command "config t"
  action 2.4    cli command "event manager environment outage_current $outage_current"
  action 2.6    cli command "end"
  !
  ! Perform router recovery from pnp when recovery timer is exceeded
  !
  action 2.8    if $outage_current gt $outage_total_limit
  action 3.0      syslog msg "Recovery timer expired. Initiating GW recovery." 
  action 3.2      cli command "enable"
  action 3.4      cli command "show platform nvram | redirect flash:iotd_recovery.log" pattern "confirm|#"
  action 3.6      cli command ""
  action 3.8      cli command "show platform hypervisor | append flash:iotd_recovery.log" pattern "#"
  action 4.0      cli command "show iox host list detail | append flash:iotd_recovery.log" pattern "#"
  action 4.2      cli command "dir /all /recursive all-filesystems | append flash:iotd_recovery.log" pattern "#"
  action 4.4      cli command "show pnp tech-support | append flash:iotd_recovery.log" pattern "#"
  action 4.6      cli command "show clock detail | append flash:iotd_recovery.log" pattern "#"
  action 4.8      cli command "show tech-support | append flash:iotd_recovery.log" pattern "#"
  action 5.0      cli command "show clock detail | append flash:iotd_recovery.log" pattern "#"
  action 5.2      cli command "show logging | append flash:iotd_recovery.log" pattern "#"
  action 5.4      cli command "delete /f flash:express-setup-config*"
  action 5.6      cli command "delete /f flash:before-registration-config*"
  action 5.8      cli command "delete /f flash:before-tunnel-config*"
  action 6.0      cli command "delete /f flash:/-*" 
  action 6.2      cli command "delete /f flash:/current_outage_timer"
  action 6.4      cli command "dir flash:/managed/bypass-discovery.cfg"
  action 6.6      regexp "-rw-" "$_cli_result"
  action 6.8      if $_regexp_result eq "0"
  action 7.0        syslog msg "*** bypass-discovery.cfg file NOT found in dir /managed, Performing full pnp ***"
  action 7.2        cli command "erase nvram:" pattern "confirm|#"
  action 7.4        cli command ""
  action 7.6        reload
  action 7.8      else
  action 8.0        syslog msg "*** bypass-discovery.cfg FOUND in flash:/managed, performing reset ***"
  action 8.2        cli command "copy flash:/managed/bypass-discovery.cfg startup-config" pattern "startup-config|#" 
  action 8.4        cli command "" 
  action 8.6        wait 10
  action 8.8        reload 
  action 9.0      end
  action 9.2    end
  action 9.4    track read 51
  action 9.6    if $_track_state eq "down"
  !
  ! Reload router when no net & OTOD connectivity outage lasts longer than configured router reload time
  !
  action 9.8      divide $outage_current $gateway_reboot_time
  action 9.81     if $_remainder eq 0
  action 9.82       syslog msg "Internet connectivity lost for $outage_current min. Attempting gateway reload"
  action 9.83       file open fd flash:/current_outage_timer w 
  action 9.84       file puts fd "$outage_current" 
  action 9.85       reload
  action 9.86     end
  !
  ! Reboot modem when no net & IOTOD connectivity outage lasts longer than configured modem reload time
  !
 <#if isFirstCell == "true">
  action 9.91     divide $outage_current $modem_reboot_time
  action 9.92     if $_remainder eq 0
  action 9.93       syslog msg "Internet connectivity lost for $outage_current min. Attempting modem reload"
  action 9.94       cli command "enable"
  action 9.95       cli command "test ${cell_if1} modem-power-cycle" pattern "#"
  action 9.96     end
  action 9.97   end 
 </#if>
  action 9.98 end
!
</#if>
!
