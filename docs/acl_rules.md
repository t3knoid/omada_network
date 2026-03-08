# ACL Rules

| Description | Status | Policy | Protocols | Source | Source Type | Destination | Destination Type | ACL Type |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Allow access for Plex to TrueNAS NFS | Enabled | Permit | TCP, UDP | plex-0 | IP Group | TRUENAS-01 NFS | IP-Port Group | gateway |
| Allow access from VLAN20 to TrueNAS NFS | Enabled | Permit | All | Infrastructure | Network | TRUENAS-01 NFS | IP-Port Group | gateway |
| Allow access from VLAN20 to TrueNAS NFS_reverse | Enabled | Permit | All | TRUENAS-01 NFS | IP-Port Group | Infrastructure | Network | gateway |
| Allow HDHomerun Access to Client VLAN | Disabled | Permit | All | HDHomeRun | IP Group | Control Plane(Default), Client | Network | switch |
| Allow HDHomerun Access to Client VLAN_reverse | Disabled | Permit | All | Control Plane(Default), Client | Network | HDHomeRun | IP Group | switch |
| Allow HTTPS access from Client to Infrastructure | Enabled | Permit | TCP | Client, Control Plane(Default) | Network | VLAN20 HTTPS | IP-Port Group | gateway |
| Allow https from rproxy-0 to backend proxy servers | Enabled | Permit | TCP | rproxy-0 | IP Group | rproxy-1 https, rproxy-2 https | IP-Port Group | gateway |
| Allow SSH from Client to DMZ network | Enabled | Permit | TCP | Client, Control Plane(Default) | Network | VLAN30 SSH | IP-Port Group | gateway |
| Allow SSH from Client to Infrastructure network | Enabled | Permit | TCP | Client, Control Plane(Default) | Network | VLAN20 SSH | IP-Port Group | gateway |
| Allow SSH from Infrastructure to DMZ | Enabled | Permit | TCP | Infrastructure | Network | VLAN30 SSH | IP-Port Group | gateway |
| Allow traffic between client and IoT networks | Disabled | Permit | All | Control Plane(Default), Client | Network | IoT Devices | Network | switch |
| Allow traffic between client and IoT networks_reverse | Disabled | Permit | All | IoT Devices | Network | Control Plane(Default), Client | Network | switch |
| Allow traffic between HDHomeRun Device and Client VLAN | Enabled | Permit | TCP, UDP | HDHomeRun | IP Group | Control Plane(Default), Client | Network | gateway |
| Allow traffic between HDHomeRun Device and Client VLAN_reverse | Enabled | Permit | TCP, UDP | Control Plane(Default), Client | Network | HDHomeRun | IP Group | gateway |
| Allow traffic between HDHomeRun Device and Plex Server | Enabled | Permit | TCP, UDP | HDHomeRun | IP Group | plex-0 | IP Group | gateway |
| Allow traffic between HDHomeRun Device and Plex Server_reverse | Enabled | Permit | TCP, UDP | plex-0 | IP Group | HDHomeRun | IP Group | gateway |
| Allow traffic from Client network  to DNS servers | Enabled | Deny | TCP, UDP | Control Plane(Default), Client | Network | DNS Cluster | IP-Port Group | gateway |
| Allow traffic from Client network to Bedrock server | Enabled | Permit | UDP | Client, Control Plane(Default) | Network | Minecraft | IP-Port Group | gateway |
| Allow traffic from DMZ network  to DNS servers | Enabled | Permit | TCP, UDP | DMZ | Network | DNS Cluster | IP-Port Group | gateway |
| Allow VLAN20 access to Synology NFS shares | Enabled | Permit | TCP, UDP | Control Plane(Default), Client | Network | SYNOLOGY NFS | IP-Port Group | gateway |
| Allow VLAN20 to Default network | Enabled | Permit | TCP, UDP, ICMP | Control Plane(Default) | Network | Infrastructure | Network | gateway |
| Allow VLAN20 to Default network_reverse | Enabled | Permit | TCP, UDP, ICMP | Infrastructure | Network | Control Plane(Default) | Network | gateway |
| Allow VPN client to access client network | Enabled | Permit | All | VPN Client | IP Group | Client | Network | gateway |
| Deny IOT access to other networks | Disabled | Deny | All | IoT Devices | Network | Control Plane(Default), Client, Infrastructure, DMZ | Network | switch |
| Deny traffic from Client VLAN to IoT VLAN | Enabled | Deny | All | Client, Control Plane(Default) | Network | IoT Devices | Network | gateway |
| Deny traffic from DMZ VLAN to Infrastructure VLAN | Enabled | Deny | All | DMZ | Network | Infrastructure | Network | gateway |
| Deny traffic from DMZ VLAN to Infrastructure VLAN_reverse | Enabled | Deny | All | Infrastructure | Network | DMZ | Network | gateway |
| Deny traffic from DMZ VLAN to IoT VLAN | Enabled | Deny | All | DMZ | Network | IoT Devices | Network | gateway |
| Deny traffic from Infrastructure VLAN to IoT VLAN | Enabled | Deny | All | Infrastructure | Network | IoT Devices | Network | gateway |
| Deny traffic from IoT VLAN to Client VLAN | Enabled | Deny | All | IoT Devices | Network | Control Plane(Default), Client | Network | gateway |
| Deny traffic from IoT VLAN to DMZ VLAN | Enabled | Deny | All | IoT Devices | Network | DMZ | Network | gateway |
| Deny traffic from IoT VLAN to Infrastructure VLAN | Enabled | Deny | All | IoT Devices | Network | Infrastructure | Network | gateway |
