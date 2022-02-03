!
! <#-- START of GW Recovery Scripts -->
! This script will reset the gateway if the connection with
! IoT OD is lost for a configurable period of time.
!
<#assign recoveryTime = far.recoveryTimer!"120">
<#if far.isRecoveryEnable?has_content && far.isRecoveryEnable == "true">
<#assign recoveryTimeIOTD = recoveryTime?number / 2>
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
  event counter name current_iotd_outage entry-val ${recoveryTimeIOTD} entry-op ge exit-op ge exit-val ${recoveryTime} maxrun 99
  action 1.0  counter name "current_iotd_outage" op nop
  action 2.0  syslog msg "IOTD current outage is: $_counter_value_remain. Checking total outage timer."
  action 3.0  if $_counter_value_remain gt $outage_total_limit
  action 3.1    syslog msg "Both timers expired. Will initiate GW recovery."
  action 3.2    counter name "current_iotd_outage" op set value 0
  action 3.3    cli command "enable"
  action 3.4    cli command "show logging | redirect flash:iotd_recovery.log" pattern "confirm|#"
  action 4.1    syslog msg "*** will attempt pnp reset ***"
  action 4.2    cli command "pnpa service reset no-prompt"
  action 5.1  else
  action 5.2    syslog msg "IOTD not reachable, but total outage limit $outage_total_limit not reached yet."
  action 5.3    break
  action 5.4  end
!
</#if>
!
<#-- END of GW Recovery Scripts -->
