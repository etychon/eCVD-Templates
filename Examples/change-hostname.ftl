<#if far.localHostName?has_content>
  <#assign HoNam = "${far.localHostName}">
<#else>
  <#assign HoNam = "local">
</#if>
!
event manager applet config_hostname
  event timer watchdog time 3
  action 1 cli command "enable"
  action 2 cli command "conf t"
  action 3 cli command "hostname ${HoNam}"
  action 4 cli command "no event manager applet config_hostname"
  action 5 cli command "end"
