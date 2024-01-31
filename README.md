# eCVD-Templates

> [!NOTE]\
> This repository is not maintained anymore.

This repository contains eCVD templates for Cisco IoT Operations Dashboard (IoT OD) Edge Device Manager (EDM). These templates are based on user feedback and testing performed by the Cisco Validated Design (CVD) team, and are meant to be used with Cisco IoT OD.

[Cisco IoT Operations Dashboard](https://developer.cisco.com/docs/iotod/) is a device management platform to manage Cisco industrial network devices such as IR1800, IR1101, IR829, IR809, and IR807. Devices are onboarded using [Cisco Plug and Play Connect](https://www.cisco.com/c/en/us/buy/smart-accounts/plug-play-connect.html). Recently, support was added to IoT OD for switches - like IE3400, IE3300 - but not for template-based configuration management. Switches are only enabled to consume IoT OD services like Cisco Cyber Vision (CCV), or Secure Equipment Access (SEA), but not to be managed by EDM. We recommend to manage switches with solutions such as Cisco Catalyst Center (previously called DNA-C).

# How it works

IoT OD will present the user with a graphical configuration template that is build based on `userPropertyTypes.xml`. Based on user input and preference, a data model is fed to the appropriate template that will generate an IOS configuration file.

![flow.png](images/flow.png)

# UPT

Written in XML with JSON payload. Make sure to validate full syntax is correct before moving to production with https://github.com/etychon/iotoc-userPropertyTypes-validator
For the moment, the UPT is part of the core product and cannot be changed by the user (but this is about to change in 2024). 
It is provided here under the `UPT` directory as a reference for all variable names and types.

# Templates

IoT OD templates are written using Apache [FreeMarker](https://freemarker.apache.org/). As you write your own template and include user options (such as Cellular APN), IoT OD user interface will provide a graphical view to enter data fields. IoT OD will only present variables that are part of the template so that you can make very simple, or very complicated templates.

The templates provided here can be used as they are, or as a basis for your own template.

The ultimate output of a template is a Cisco IOS configuration that will be pushed to the gateway.

How to use templates provided here in Cisco IoT Operations Dashbord is explained in [Cisco DevNet IoT OD documentation](https://developer.cisco.com/docs/iotod/#!manage-templates-and-groups/add-and-manage-configurations).

# Templates Future

Going forward the plan is to have fully managed templates that won't be editable by the user. This will allow for seamless template upgrades without loosing local user changes and customizations. However customization will still be possible by adding custom configuration CLI items. 

This change will mark a clear demarcation point between Cisco-provided template, and user-provided changes and customization reducing the friction zone between the two. 

# Templates (Version 2)

This repo contains the new v2 templates for IR829 and IR1101. You can differentiate them as they have `v2` in their name (ie: `eCVD-IR1101-v2.ftl`)

Version 2 templates are automatically tested in Cisco IoT OD regression test suite, which means we have validated that we have not introduced any issues (regression issue) for each production update of Cisco IoT OD.

Version 1 templates are not tested.

# Templates (Version 1)

This repo contains v1 templates for IR829, IR1101, and IR829's access point (AP803). They are two versions of the templates: Basic (B) and Advanced (A).

**The version 1 templates are not tested as part of the product validation**


The table below lists what's supported by each template type, either `A` for Advanced, `B` for Basic, and `A+B` for both:

| Feature                                         | IR829 | IR1101 |
|-------------------------------------------------|:----------:|:------:|
| Interface routing priority                            | A+B | A+B |
| LTE Support                                           | A+B | A+B |
| Second LTE Support                                    | A   |  A  |
| Cellular custom APN configuration                     | A+B | A+B |
| Enable/Disable Subtended ports                        | A+B| A+B |
| Subtended network IP configuration                    | A+B | A+B |
| Subtended network DHCP exclusion range                | A+B | A+B |
| Configurable ICMP destination for IP SLA reachability | A | A |
| Workgroup Bridge (Wifi client)                        | A | - |
| Wifi AP with pre-shared key                           | A | - |
| Cisco Umbrella Token                                  | - | A |
| Cisco Umbrella Exclusion RegExp                       | - | A |
| Netflow                                               | A | A |
| Custom Firewall Rules                                 | A | A |
| VPN Headend primary and backup                        | A+B | A+B |
| VPN Interface Source Selection                        | A+B | A+B |
| NTP                                                   | A+B | A+B |
| QoS for Cellular upstream                             | A | A |
| Port Forwarding rules                                 | A+B | A+B |
| Additional static routes                              | A | A |
| Local user configuration                              | A+B | A+B |
| Interface failover using IP SLAs                      | A+B | A+B |

Note:
* IR829s have two templates: one for the gateway, one for the Access Point.
* The default upstream ethernet port is Gig0/0/0 for IR1101 and Gig1 for IR829.

# References
