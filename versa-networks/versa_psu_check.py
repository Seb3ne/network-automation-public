#!/usr/bin/env python3.8
"""
Name & Description: Versa Networks power supply script - Detect faulty/missing power supply modules
Credits: Copied ssh authentication block from (verify-cisco-mt.py) by Chris B.
Author: Angelo Kwassivi
Date: Aug 08 2022
Version 1.0
"""

import getpass
# from typing import final
import os
import re
import time
from datetime import datetime

import paramiko

# import threading

BANNER = """
 _  _  ____  ____  ____   __     ____  ____  _  _     ___  _  _  ____  ___  __ _ 
/ )( \(  __)(  _ \/ ___) / _\   (  _ \/ ___)/ )( \   / __)/ )( \(  __)/ __)(  / )
\ \/ / ) _)  )   /\___ \/    \   ) __/\___ \) \/ (  ( (__ ) __ ( ) _)( (__  )  ( 
 \__/ (____)(__\_)(____/\_/\_/  (__)  (____/\____/   \___)\_)(_/(____)\___)(__\_)
"""

USR_MSG = "\n###### Please type in your credentials. ######"

print(BANNER)
print(USR_MSG)

UN = input("Username : ")
PW = getpass.getpass("Password : ")
IPS_LIST = input("What is the filename containing the list of IPs? (include absolute path): ")
# datetime object containing current date and time
now = datetime.now()

print(f"\nStart time = {datetime.now()} \n")

# Dictionary to store all faulty devices
FAULTY_DEVICES = {

}

# List of codes to check based on firmware version
ERROR_CODES = {
    "1.04": ["0x0100", "0x0800"],
    "1.10": ["0x0100", "0x0800"],
    "1.08": ["0x0000", "0x0800", "0x0900", "0x0a00", "0x0b00"],
}

# Dictionary of meanings based on firmware version
MEANINGS = {
    "1.04": {
        "0x0100": "Empty power supply slot",
        "0x0800": "AC lost or Failure detected",
    },
    "1.10": {
        "0x0100": "Empty power supply slot",
        "0x0800": "AC lost or Failure detected",
    },
    "1.08": {
        "0x0000": "Empty power supply slot",
        "0x0800": "Empty power supply slot",
        "0x0900": "AC lost. PSU is unplugged",
        "0x0a00": "Power cord unplugged",
        "0x0b00": "Power Supply AC lost",
    },
}

# Files to store different output based on issues
EMPTYSLOT = "emptyslot.txt"
FAULTYPSU = "faultypsu.txt"
SSH_FAILED = "ssh_failure.txt"

HOSTLIST = open(IPS_LIST, "r").readlines()


def get_snmp_info(session):
    """returns the hostname, site address and email of the snmp owner"""
    host_loc_owner = []
    session.send("show configuration snmp system\n")
    time.sleep(1)
    raw_snmp = session.recv(99999)
    snmp = raw_snmp.decode("ascii")
    for line in snmp.splitlines():
        if "name" in line:
            host_loc_owner.append(line.split()[1])
        if "location" in line:
            host_loc_owner.append(line.split('"')[1])
        if "contact" in line:
            host_loc_owner.append(line.split()[1])

    return host_loc_owner


def firmware_check(session):
    """returns current firmware version"""
    session.send("sudo ipmitool mc info | grep Firmware\n")
    time.sleep(1)
    raw_version = session.recv(99999)
    version = raw_version.decode("ascii")
    for line in version.splitlines():
        if "1.04" in line:
            return "1.04"
        elif "1.08" in line:
            return "1.08"
        elif "1.10" in line:
            return "1.10"


def sensor_code_check(session, version):
    """check for codes based on firmware version and returns a list of psu#, codes found and meanings"""
    if version in ERROR_CODES:
        findings = []

        session.send("sudo ipmitool sensor | grep -i PSU\n")
        time.sleep(1)
        raw_response = session.recv(99999)
        decoded_response = raw_response.decode("ascii")
        # print(decoded_response)

        for line in decoded_response.splitlines():
            for code in ERROR_CODES[version]:
                if code in line:
                    number = line.split("|")[0]
                    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
                    psu_number = ansi_escape.sub('', number)
                    psu_number = psu_number.strip()
                    # print(psu_number)
                    code_meaning = MEANINGS[version][code]
                    findings = [psu_number, code, code_meaning]
        return findings
    else:
        return []


def psu_check(list_of_hosts):
    if os.path.exists(EMPTYSLOT):
        os.remove(EMPTYSLOT)
    if os.path.exists(FAULTYPSU):
        os.remove(FAULTYPSU)
    if os.path.exists(SSH_FAILED):
        os.remove(SSH_FAILED)

    for host in list_of_hosts:
        host = host.strip()
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            print(host)
            ssh.connect(hostname=host, port=22, username=UN, password=PW, look_for_keys=False)
            print(f"###### sshd into & working on {host} ######")
            channel = ssh.invoke_shell()
        except paramiko.AuthenticationException:
            print('###### Error: Username / password is incorrect ######')
            auth_fail = open(SSH_FAILED, "a+")
            auth_fail.write(f"{host} : ###### Error: Username / password is incorrect ######\n")
            auth_fail.close()
        except paramiko.ssh_exception.NoValidConnectionsError:
            print('###### Error: Unable to Establish SSH session ######')
            auth_fail = open(SSH_FAILED, "a+")
            auth_fail.write(f"{host} : ###### Error: Unable to Establish SSH session ######\n")
            auth_fail.close()
        except paramiko.ssh_exception.SSHException:
            print('###### Error: No existing session ######')
            auth_fail = open(SSH_FAILED, "a+")
            auth_fail.write(f"{host} : ###### Error: No existing session ######\n")
            auth_fail.close()
        else:
            print(f"###### shell channel to {host} is established ######")
            time.sleep(1)
            channel.recv(1000)

            ######################################################################

            snmp_details = get_snmp_info(channel)
            # print(snmp_details)
            channel.send("shell\n")
            # time.sleep(2)
            firmware = firmware_check(channel)
            # print(firmware)
            issue = sensor_code_check(channel, firmware)
            # print(issue)

            if issue != []:
                # final_result = [host, issue, snmp_details[2], snmp_details[0],]
                final_result = [host, ]
                for _ in issue:
                    final_result.append(_)
                # final_result.append(host)
                # final_result.append(issue)
                final_result.append(snmp_details[2])
                final_result.append(snmp_details[0])
                FAULTY_DEVICES[snmp_details[1]] = final_result

                ######################################################################
            time.sleep(5)
            ssh.close()
            print(f"###### Closed ssh connection to {host} ######\n")

    ######################################################################
    # print(FAULTY_DEVICES)
    if FAULTY_DEVICES != {}:
        for key in FAULTY_DEVICES:
            # print(key, FAULTY_DEVICES[key])
            if FAULTY_DEVICES[key][3] == "Empty power supply slot":
                missing_psu = open(EMPTYSLOT, "a+")
                missing_psu.write(f"{key} {FAULTY_DEVICES[key]}\n")
                missing_psu.close()
            elif FAULTY_DEVICES[key][3] != "Empty power supply slot":
                actionable_psu = open(FAULTYPSU, "a+")
                actionable_psu.write(f"{key} {FAULTY_DEVICES[key]}\n")
                actionable_psu.close()

    print(f"\nEnd time = {datetime.now()} \n")
    print('######     The End     ######\n')


psu_check(HOSTLIST)
