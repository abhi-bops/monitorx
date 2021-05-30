import shlex
import subprocess
import socket
import sys
from math import asin, cos, sqrt, pi

def run_command(command, timeout=None):
    """
    Runs a command in bash shell. 

    This copy exists in all the parse crypts to exist as standalone.
    So, any changes needs to be copied over to others too for consistency. :(

    Parameters
    ----------
    command : str or list
       command that needs to be run in the bash shell. If its a str, that command will be executed. 
    If it's a list, the commands will be piped and the final output returned.

    Returns
    -------
    tuple
       1. output - output lines from the command result
       2. error - error lines from stderr
       3. err_code - error code of the command result
    """
    if type(command) != list:
        command = [command]
    cmd = shlex.split(command[0])
    process = subprocess.Popen(cmd, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    prev_process = process #Assign this process as prev_process so that the variables make sense later
    for cmd in command[1:]:
        cmd = shlex.split(cmd)
        #prev_process is the process that was run before the current iteration of loop
        process = subprocess.Popen(cmd, shell=False, stdin=prev_process.stdout, stdout=subprocess.PIPE, stderr=subprocess.PIPE) 
        prev_process.stdout.close() #Close the stdout of the previous process, as we don't need it
        prev_process = process #Assign the process in the current iteration of the loop as the current process
    #Handling timeouts
    if timeout:
        try:
            process.communicate(timeout=timeout)
        except TimeoutExpired:
            process.kill()
    result = process.communicate()
    err_code = process.returncode
    output = result[0].decode("utf-8")
    error = result[1].decode("utf-8")
    return output, error, err_code

def clean_split(line):
    return list(map(lambda x:x.strip(), line.split()))

def get_ip_asn_data(ip_set):
    """
    Usage doc : https://team-cymru.com/community-services/ip-asn-mapping/
    """
    ip_set = set(ip_set)
    cy = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    cy.connect(("whois.cymru.com", 43))
    query = 'begin\nasname,asnumber\n' + '\n'.join(ip_set) + '\nend\n'
    #Python 3 needs a byte object passed
    if sys.version_info.major == 3:
        query = query.encode('utf-8')
    cy.sendall(query)
    response = ''
    while True:
        r = cy.recv(10)
        #Result will be a byte, converting it into string
        if sys.version_info.major == 3:
            r = r.decode()
        if r and r != '':
            response += r
        else:
            break
    cy.close()
    labels = ['asnum', 'ip', 'company']
    ip_dict = {}
    for line in response.split('\n'):
        if line == '' or line.startswith('Bulk'):
            continue
        info = [word.strip() for word in line.split('|')]
        ip_dict[info[1]] = dict(zip(labels, info))
        #company name in output includes the country of the company, remove it
        ip_dict[info[1]]['company'] = ','.join(ip_dict[info[1]].get('company', '').split(',')[:-1])
    return ip_dict

def haversine(p1=None, p2=None):
    """
    Compute the distance between 2 points in a globe. The points are represented as a tuple
    of latitide and longitude of the location. Code from https://stackoverflow.com/a/21623206

    Parameters
    ----------
    p1: tuple
       Latitude and Longitude values of point1

    p2: tuple
       Latitude and Longitude values of point2

    Returns
    -------
    float
       The distance between those points (calculated using the haversine formula
    """
    lat1, lon1 = p1
    lat2, lon2 = p2
    p = pi/180
    a = 0.5 - cos((lat2-lat1)*p)/2 + cos(lat1*p) * cos(lat2*p) * (1-cos((lon2-lon1)*p))/2    
    return 12742 * asin(sqrt(a)) #2*R*asin...

def is_ip(address):
    """Check if its a valid IP address.                                                                                                                                         
    http://stackoverflow.com/questions/319279/how-to-validate-ip-address-in-python                                                                                              
    """
    try:
        socket.inet_pton(socket.AF_INET, address)
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, address)
        except socket.error:
            return False
    return True

def sortip(ips):
    return sorted(ips, key=lambda x: [int(i) for i in x.split('.')])

def pretty_print_table(result, heading=False):
    """
    Prints the query result in a human friendly format
    """
    # If the data is not in string, then it is likely a text format
    if type(result) == 'str':
        result = result.split('\n')
        result = [line.split() for line in result]
    #Remove empty items
    result = [row for row in result if row!=['']]

    columns = len(result[0])  #Get the number of columns, this is used for row formatting
    row_format = '' #variable to construct the row formatting
    
    # Calculating the max length for each column
    for i in range(0, columns):
        # picking the length of the longest element
        #Need to convert the elements into string
        MAX_LEN = len(max([str(row[i]) for row in result], key=len))
        # Constructing the string formatting
        row_format += "{:<" + str(MAX_LEN) + "} | "

    pretty_result = ''
    if heading:
        pretty_result = row_format.format(*result[0]) + '\n'
        pretty_result += len(row_format.format(*result[0])) * "-" + '\n'
        result = result[1:]
    for row in result:
        pretty_result += row_format.format(*row) + '\n'
    return pretty_result

def IsPrivateIP(ip):
    """Borrowed from log_analysis.py"""
    return addressInNetwork(ip, "10.0.0.0/8") or addressInNetwork(ip, "172.16.0.0/12") or addressInNetwork(ip, "192.168.0.0/16") or addressInNetwork(ip, "127.0.0.1/32") or addressInNetwork(ip, "100.64.0.0/10")

def log(info=None):
    print('[{}] : {}'.format(datetime.datetime.now(), info))
