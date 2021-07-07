<#-- This template will factory reset -----
  -- a gateway forcing it to re-do PnP  ---
  -----------------------------------------
  -- Version 1.0 --------------------------
-->

event manager directory user policy "flash:/managed/scripts"

event manager applet FACTORY-RESET-WARN
 event timer countdown time 120 maxrun 300
 action 1.04 syslog msg  "**********"
 action 1.05 syslog msg  "A factory reset will be triggered in one minute!"
 action 1.06 syslog msg  "To cancel it do:"
 action 1.07 syslog msg  "conf t"
 action 1.08 syslog msg  "no event manager applet FACTORY-RESET"
 action 1.09 syslog msg  "**********"

event manager applet FACTORY-RESET
 event timer countdown time 180 maxrun 300
 action 1.0 cli command "enable"
 ! do erase and reload
 action 1.05 syslog msg  "EEM applet will trigger factory reset now"
 action 1.06 cli command "del /f -*"
 action 1.07 cli command "del /f /r pnp*"
 action 1.08 cli command "del /f /r archive*"
 action 1.09 cli command "del /f before*"
 action 2.01 cli command "erase nvram:" pattern "confirm|#"
 action 2.02 cli command ""
 action 2.03 reload
 
