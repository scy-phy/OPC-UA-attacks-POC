import os.path
import os
import re
from utils.port_scanner import scan_port
from opcua import Client, ua, tools
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

identity_tokens_dict = {'anonymous': 'Anonymous',
                        'certificate_basic256sha256': 'Basic256Sha256',
                        'username': 'Username'
                        }


def connect_to_server(client, url, endpoint, found_info):
    """
    connect to the selected server with the rogue client
    
    scan the server nodes recursively and store found informations in the results folder

    Parameters
    ----------
    client : [client]
        [rogue client configured]
    url : [string]
        [address of the target server]
    endpoint : [string]
        [endpoint string]
    found_info : [dict]
        [info about the server]
    """
    try:
        client.connect()
        print('|\t|\t|->Succesfully Connected')
    except ConnectionRefusedError:
        print('|\t|\t|->Connect Refused by:  ' +
              str(url)+' Endpoint:'+str(endpoint))
    root = client.get_root_node()
    try:
        found_info['Nodes'] = browse_recursive(client, root)
    except:
        found_info['Nodes'] = 'failed to explore node'
    client.disconnect()

    if not os.path.exists('./results/'+str(url)):
        os.makedirs('./results/'+str(url))
    try:
        with open('./results/'+str(url)+'/'+str(found_info['SecurityMode'])+'_'+str(found_info['SecurityPolicy']), 'a') as f:
            f.write(str(found_info))
    except FileNotFoundError:
        try:
            path = './results/'+str(url)+'/'
            os.mkdir(path)
        except OSError:
            print("Creation of the directory %s failed" % path)
        else:
            print("Successfully created the directory %s " % path)
        with open('./results/'+str(url)+'/'+str(found_info['SecurityMode'])+'_'+str(found_info['SecurityPolicy']), 'a') as f:
            f.write(str(found_info))


def connect_without_session_creation(client):
    """
    connect to the selected withouth creating a session
    
    Parameters
    ----------
    client : [client]
        [rogue client]
    """
    client.connect_socket()
    try:
        client.send_hello()
        client.open_secure_channel()
    except Exception:
        client.disconnect_socket()  # clean up open socket
        raise


def browse_recursive(client, node):
    """
    Identify all the nodes published by the endpoint on the server

    Parameters
    ----------
    client : [client]
        [rogue client]
    node : [node]
        [node to explore]

    Returns
    -------
    [list]
        [list of nodes]
    """
    
    list_nodes = []
    for childId in node.get_children():
        ch = client.get_node(childId)
        if ch.get_node_class() == ua.NodeClass.Object:
            list_nodes.append(browse_recursive(client, ch))
        elif ch.get_node_class() == ua.NodeClass.Variable:
            try:
                try:
                    list_nodes.append(
                        [ch.get_browse_name(), str(ch.get_value())])
                except:
                    list_nodes.append([ch.get_browse_name(), 'None'])
            except ua.uaerrors._auto.BadWaitingForInitialData:
                pass
    return list_nodes

def start_rogue_client_with_credentials(server_url, port):
    """
    Rogue client setup with credentials (extracted from the file store with the rogue server)
    
    Try to connect automatically to all offered endpoints

    Parameters
    ----------
    server_url : [string]
        [target server address]
    port : [string]
        [target server port]
        
    """
    with open('stolen_credentials.txt', 'r') as f:
        stolen_credentials = eval(f.read())
    url = server_url+':'+port
    client = Client('opc.tcp://'+str(url))
    endpoints = client.connect_and_get_server_endpoints()
    client.set_user(stolen_credentials['username'])
    client.set_password(stolen_credentials['password'])
    server_enpoints = []
    for endpoint in endpoints:
        # extract security mode for the given enpoint: None, Sign, SignAndEncrypt
        found_info = {}
        found_info['SecurityMode'] = re.findall(
            r'\.(\w+)', str(endpoint.SecurityMode))[0]
        found_info['SecurityPolicy'] = re.findall(
            r'#(\w+)', endpoint.SecurityPolicyUri)[0]

        found_info['identitytokens'] = []
        for tok in endpoint.UserIdentityTokens:
            found_info['identitytokens'].append(
                identity_tokens_dict[tok.PolicyId])
        server_enpoints.append(found_info)
        cert = os.path.join(os.path.dirname(__file__), 'certificate.pem')
        key = os.path.join(os.path.dirname(__file__), 'key.pem')
        if found_info['SecurityPolicy'] != "None":
            string = ""+found_info['SecurityPolicy']+"," + \
                found_info['SecurityMode']+","+cert+","+key
            client.application_uri = "urn:example.org:FreeOpcUa:python-opcua"
            client.set_security_string(string)
        connect_to_server(client, url, endpoint, found_info)
    
def start_rogue_client(server_url, port):
    """
    Rogue client startup without credentials (if credentials are required the program asks for them)
    
    Try to connect automatically to all offered endpoints

    Parameters
    ----------
    server_url : [string]
        [target server address]
    port : [string]
        [target server port]
    """
    url = server_url+':'+port
    results_path = os.path.join(os.path.dirname(__file__), 'results/')
    if not os.path.exists(results_path):
        os.makedirs(results_path)
    print('Scanning the following OPC UA servers:')
    print('|---> URL: '+str(url))
    client = Client('opc.tcp://'+str(url))
    endpoints = client.connect_and_get_server_endpoints()
    print('|\t# Endpoints:'+str(len(endpoints)))
    server_enpoints = []
    for endpoint in endpoints:
        print('|\t|---> Scanning Enpoint')
        string_endpoints = tools.endpoint_to_strings(endpoint)
        # extract security mode for the given enpoint: None, Sign, SignAndEncrypt
        found_info = {}
        found_info['SecurityMode'] = re.findall(
            r'\.(\w+)', str(endpoint.SecurityMode))[0]
        found_info['SecurityPolicy'] = re.findall(
            r'#(\w+)', endpoint.SecurityPolicyUri)[0]

        print('|\t|\t|->Security Mode: ', found_info['SecurityMode'])
        print('|\t|\t|->Security Policy: ', found_info['SecurityPolicy'])

        found_info['identitytokens'] = []
        for tok in endpoint.UserIdentityTokens:
            found_info['identitytokens'].append(
                identity_tokens_dict[tok.PolicyId])
        server_enpoints.append(found_info)
        cert = os.path.join(os.path.dirname(__file__), 'certificate.pem')
        key = os.path.join(os.path.dirname(__file__), 'key.pem')
        if found_info['SecurityPolicy'] != "None":

            string = ""+found_info['SecurityPolicy']+"," + \
                found_info['SecurityMode']+","+cert+","+key
            # Should match in your certificate
            client.application_uri = "urn:example.org:FreeOpcUa:python-opcua"
            client.set_security_string(string)
        if 'Anonymous' in found_info['identitytokens']:
            connect_to_server(client, url, endpoint, found_info)
        else:
            print('|\t|\t|Found the following user identity tokens: ' +
                  str(found_info['identitytokens']))
            print('|\t|\t|you need credentials to perform ActivateSession')
            print('|\t|\t|trying the OpenSecureChannel request to verify')
            print('|\t|\t|the certificate management on server side')
            try:
                connect_without_session_creation(client)
                print('|\t|\t|\t|->Succesfully enstablished a secure channel')
                client.disconnect()
                if 'Username' in found_info['identitytokens']:
                    answer = str(
                        input('Do you own user credentials? (y/n)   '))
                    if answer == 'n':
                        print('please try to steal credentials with')
                        print('Person in The Middle Attack')
                    if answer == 'y':
                        import getpass
                        user = input('Username:')
                        password = getpass.getpass('Password:')
                        client.set_user(user)
                        client.set_password(password)
                        connect_to_server(client, url, endpoint, found_info)

            except ConnectionRefusedError:
                print('|\t|\t|->Connect Refused by:  ' +
                      str(url)+' Endpoint:'+str(endpoint))

    print('|')
    print('Scan completed')