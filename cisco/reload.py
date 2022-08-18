#!/bin/python3.8
# Author: Angelo Kwassivi
# 
# Objective: Safely reload Cisco C3850/3650 impacted by Cisco bug CSCvd45973 (https://quickview.cloudapps.cisco.com/quickview/bug/CSCvd45973)
#
# Version 
#   1.0 - 07/29/2022
#   2.0 - 08/14/2022
#       + save_run_config()
#       + save pre & post check logs locally
#
# Requirements:
#   input.txt: file containing the list of IPs/hostnames to reload. One IP/hostname per line
#   reload_cmds.py: list of pre/post commands per OSI layer
#   
# Credits: https://github.com/ktbyers/netmiko

#### Notes To Self ######
#host for variables and functions
#devices for actual items

#Modules
from getpass import getpass
from netmiko import ConnectHandler, SSHDetect
from selectors import BaseSelector
from time import sleep
from datetime import datetime
import os
from reload_cmds import cmds

BANNER = """
                  dP                         dP     a88888b. d8888b. .d888b. 888888P  a8888a  
                  88                         88    d8'   `88     `88 Y8' `8P 88'     d8' ..8b 
88d888b. .d8888b. 88 .d8888b. .d8888b. .d888b88    88         aaad8' d8bad8b 88baaa. 88 .P 88 
88'  `88 88ooood8 88 88'  `88 88'  `88 88'  `88    88            `88 88` `88     `88 88 d' 88 
88       88.  ... 88 88.  .88 88.  .88 88.  .88    Y8.   .88     .88 8b. .88      88 Y8'' .8P 
dP       `88888P' dP `88888P' `88888P8 `88888P8     Y88888P' d88888P Y88888P d88888P  Y8888P  
oooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooooo
"""
print(BANNER)
#Variables - Global Scope
## User credentials
## List of devices
# 1. Define list of hosts from file
# 1.a. Define list of commands per layer
# 1.b. Get user credentials
DEVICES = open("input.txt").read().splitlines()
print(f"Warning! The following devices will be reloaded. If you do recognize one of them, press CTRL + C immediately:\n{DEVICES}")
USERNAME = input("\nUsername: ")
PASSWORD = getpass("Password: ")

LAYER_1 = cmds["show"]["layer_1"]
LAYER_2 = cmds["show"]["layer_2"]
LAYER_3 = cmds["show"]["layer_3"]
# LAYER_1 =["show ver", "show int des",]
# LAYER_2 =["show mac add", "show spann",]
# LAYER_3 =["show ip int br", "show ip route",]

#Log files
PRE_LOG = "prechecklog.txt"
POST_LOG = "postchecklog.txt"
NOT_COMPATIBLE = "not_compatible.txt"

if os.path.exists(PRE_LOG):
    os.remove(PRE_LOG)
if os.path.exists(POST_LOG):
    os.remove(POST_LOG)
if os.path.exists(NOT_COMPATIBLE):
    os.remove(NOT_COMPATIBLE)
#Functions
##reload(list_of_hosts)
##ssh(host)
##check(list)
def ssh(host):
    """ssh to the host and returns the session attributes in a variable"""
    return ConnectHandler(**host)

def is_compatible(host):
    """check the host to see if it is a cisco_ios type"""
    return SSHDetect(**host).autodetect()

def save_run_config(session, host):
    """ save the running config to a local file named after the device IP or hostname """
    session.send_command(
        command_string='terminal length 0',
        read_timeout=90)
    show_run = session.send_command(
        command_string='show running',
        read_timeout=90)
    config_file = f"{host['ip']}_running_config.txt"
    run_config = open(config_file, "w")
    run_config.write(show_run)
    run_config.close()


def run_commands(list_of_commands, session, logfile):
    """sends the list of commands one line at time to the ssh session previously created. The output is captured, printed on the screen and save into a logfile"""
    for command in list_of_commands:
        output = session.send_command(command)
        logfile.write(f"========= {command} =========\n{output}\n")
        if "Invalid" in output:
            print(f"========= {command} =========")
            print("Invalid command\n")
        else:
            print(f"========= {command} =========")
            print(output)

def ping(ip, same_chassis, times):
    """loop ping until the device is reachable or X=times time. Then skip the chassis"""
    same_chassis = True
    number = 0

    print(f'\n========= Pinging {ip} every 10 secs =========')

    is_reachable = False
    while not is_reachable:
    # add '.0' to '100%' for Apple terminal
        ping_cmd = os.popen(f'ping -c 1 -W 1 {ip} | grep -q "100% packet loss" && echo "0" || echo "1"').read().splitlines()
        ping_response = ping_cmd[0]
        
        
        if ping_response == "0":
            print(f'{ip} is unreachable')
            number += 1
            sleep(10)
        
        elif ping_response == "1":
            is_reachable = True
            print(f'\n>>> {ip} is back online <<<\n')
            return 'reachable'

        if number == times:
            #log the ip and skip
            is_reachable = True
            print("      !!!   WARNING      !!!   ")
            print(f"The device {ip} did not recover after 20 mins. Abort this script with CTRL + C.")
            print(f"Engage the local point of contact for investigation.")
            print("      !!!   WARNING      !!!   ")
            return
    
def reload(list_of_hosts):

# Define the host variable type
    for ipv4 in list_of_hosts:
        host = {
            'device_type': 'autodetect',
            'ip': ipv4 ,
            # 'port': '7663',
            'username': USERNAME,
            'password': PASSWORD,
        }

# Conditions to start the reload
        ios_version = is_compatible(host)
        if ios_version == 'cisco_ios':
            #update the device type
            host["device_type"] = 'cisco_ios'
            
            # Get the log files ready for write
            pre_log = open(PRE_LOG, "a+")
            post_log = open(POST_LOG, "a+")

            #print connecting banner
            starting_banner = f"""
            ################################################
            ########## Connecting to {host["ip"]} ##########
            ################################################
            """
            print(starting_banner)
            pre_log.write(f"{datetime.now()}")
            pre_log.write(starting_banner)

            #Should we move onto the next chassis?
            done_with_this_chassis = False

            while not done_with_this_chassis:
        # 2. SSH to host
        ## Call function to ssh: ssh(host)
                ssh_connect = ssh(host)

        # 2.a. Save the running config locally
                save_run_config(ssh_connect, host)

        # 3. Run and capture output of the pre-check commands
                print('\n#################### Layer 1 ###################')
                run_commands(LAYER_1, ssh_connect, pre_log)
                print('\n#################### Layer 2 ###################')
                run_commands(LAYER_2, ssh_connect, pre_log)
                print('\n#################### Layer 3 ###################')
                run_commands(LAYER_3, ssh_connect, pre_log)

                prompt = input(f"\nWould you like to proceed with reload of {host['ip']}? Type 'yes' or 'no': ")
                if prompt == "yes":
                    print("\n==== Saving configuration & Reloading the device ====\n")
                    pre_log.write("\n==== Saving configuration & Reloading the device ====\n")
                    print(ssh_connect.send_command("write", read_timeout=90))
                    print(ssh_connect.send_command(
                    command_string='reload in 001',
                    expect_string=r'confirm',
                    read_timeout=90
                    ))
                    
                    pre_log.write(f"{datetime.now()}")
                    pre_log.write("\n####################   END   ###################\n\n\n")
                    pre_log.close()
        # 4. Terminate session
                    ssh_connect.disconnect()
                    print(f"\n\nDisconnected from {host['ip']}\nIf you wish to cancel the reboot, log back in and issue the command 'reload cancel'.\nOtherwise the device will reload in 1 min. ")
                    sleep(70)
        # 5. Start a continuous ping
                    if ping(host["ip"], done_with_this_chassis, 120) == "reachable":
                        post_log.write(f"{datetime.now()}")
                        post_log.write(starting_banner)
        # 6. Re-SSH to host
                        ssh_connect = ssh(host)
        # 7. Run post-check commands
                        print('\n############### Post-Verification ###############\n')
                        print('\n#################### Layer 1 ###################')
                        run_commands(LAYER_1, ssh_connect, post_log)
                        print('\n#################### Layer 2 ###################')
                        run_commands(LAYER_2, ssh_connect, post_log)
                        print('\n#################### Layer 3 ###################')
                        run_commands(LAYER_3, ssh_connect, post_log)
                        ending_banner = '\n####################   END   ###################\n\n\n\n'
                        print(ending_banner)
                        post_log.write(f"{datetime.now()}")
                        post_log.write(ending_banner)
                        post_log.close()
                        ssh_connect.disconnect()
                        done_with_this_chassis = True
                    else:
                        pre_log.write("Invalid answer\n")
                        post_log.write("Invalid answer\n")
                        pre_log.close()
                        post_log.close()
                        ssh_connect.disconnect()
                        done_with_this_chassis = True

                else:
                    abort_banner = f"\n========= Aborting the reload of {host['ip']} =========\n\n\n\n"
                    print(abort_banner)
                    pre_log.write(f"{datetime.now()}")
                    post_log.write(f"{datetime.now()}")
                    pre_log.write(abort_banner)
                    post_log.write(abort_banner)
                    pre_log.close()
                    post_log.close()
                    ssh_connect.disconnect()
                    done_with_this_chassis = True
        # 8. Exit

        else:
            not_compatible_banner = f'\nThe platform for the device with ip {host["ip"]} is {ios_version} which is not supported by the script.\n'
            print(not_compatible_banner)
            not_compatible = open(NOT_COMPATIBLE, "a+")
            not_compatible.write(not_compatible_banner)
            not_compatible.close()


reload(DEVICES)
