<#-- This template will factory reset -----
  -- a gateway forcing it to re-do PnP  ---
  -----------------------------------------
  -- Version 1.0 --------------------------
-->

event manager applet FACTORY-RESET-WARN
 event timer countdown time 5 maxrun 300
 action 1.4 syslog msg  "**********"
 action 1.5 syslog msg  "A factory reset will be triggered in one minute!"
 action 1.6 syslog msg  "To cancel it do:"
 action 1.7 syslog msg  "conf t"
 action 1.8 syslog msg  "no event manager applet FACTORY-RESET"
 action 1.9 syslog msg  "**********"

event manager applet FACTORY-RESET
 event timer countdown time 65 maxrun 300
 action 1.0 cli command "enable"
 ! do erase and reload
 action 1.5 syslog msg  "EEM applet will trigger factory reset now"
 action 2.1 cli command "erase nvram:" pattern "confirm|#"
 action 2.2 cli command ""
 action 2.3 reload
end
