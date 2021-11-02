import sys 
import socket 
from datetime import datetime 

def find_servers_and_select(message_to_display):
    '''
    search servers on the network 
    
    select the server that you want to clone
    '''
    servers = scan_port(port=4840)
    print('The following servers are available: ')
    i = 0
    for server in servers:
        print(str(i)+': '+str(server))
        i = i+1
    selected_server = int(input(message_to_display+'\n (options: '+str([j for j in range(0,i)])+')  '))
    try:
        tr = servers[selected_server]
    except IndexError:
        print('selected server not in list')
        exit()
    return servers[selected_server]

def scan_port(port=4840):
    '''
    Port scanning, default port 4840
    '''
    servers = []
    for i in range(0,10):
        for j in range(0,10):
            for k in range(0,10):
                target = socket.gethostbyname('127.'+str(i)+'.'+str(j)+'.'+str(k)) 
                try: 
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM) 
                    socket.setdefaulttimeout(1) 
                    result = s.connect_ex((target,port)) 
                    if result == 0: 
                        print("-" * 50) 
                        print("found OPC UA server at: " + target) 
                        servers.append(target)
                    s.close() 
                        
                except socket.gaierror: 
                        print("\n Error: Hostname Could Not Be Resolved") 

                except socket.error: 
                        print("Error: Server not responding") 
    return servers