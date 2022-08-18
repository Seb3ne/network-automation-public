#!/bin/python3.8
# Author: Angelo Kwassivi
# Description:  list of pre/post commands per OSI layer
# Related to: reload.py

cmds = {
    "show" : {
            "layer_1" : ["show ver | in uptime|ast|INSTALL|Cisco IOS Software", "show switch", "show switch stack-ports", "show post | include Switch|Status", "show diagnostic post | include Switch|Status", "show environment all | in SYSTEM|PWR", "show plat soft stat con b", "show ip interface brief | exclude unassign", "show protocols | ex down", "show interface status | in err", "show interfaces transceiver detail", "show int po1 | inc line|minute"],
            "layer_2" : ["show mac address-table", "show ip arp", "show etherchannel summary", "show interface trunk", "show spanning-tree sum", "show spanning-tree detail | in ieee|from|occur|is exec", "show vlan | include Gi", "show lldp neighbors", "show cdp neighbors"],
            "layer_3" : ["show ip protocols", "show ipv6 protocols", "show ip ospf neighbor", "show ip ospf neighbor detail | in Neighbor|up for", "show ospfv3 ipv4 neighbor ", "show ospfv3 ipv6 neighbor ", "show ospfv3 neighbor detail | in up for", "show run | i ipv6 address", "show run | i ip address", "show ip bgp sum | begin N"],
            "restart" : ["write", "reload in 001"],
            "show_tech" : ["show tech-support | redirect flash:/tech-support.txt"] 
    },
    
    "config" : {
        "house_keeping" : ["no errdisable detect cause gbic-invalid", "service unsupported-transceiver", "no vstack"],
    }
}
