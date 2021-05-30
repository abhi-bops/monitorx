from collections import defaultdict
from math import floor
from datetime import datetime
from utils import run_command, clean_split
import sys

class Curl(object):
    curl_default_options = " -s -v -i -o /dev/null --trace-time -w 'curlout:%{speed_download}:%{time_namelookup}:%{time_connect}:%{time_appconnect}:%{time_pretransfer}:%{time_starttransfer}:%{time_total}' "

    def __init__(self, hostname, custom_hdr=None):
        """
        inputs:
        hostname: URL of the resource to fetch using curl.
        custom_hdr: Additional custom headers to use (Sometimes it is pragma headers relevant to CDNs)

        attributes:
        log: 
        d:
        command:
        req_hdr:
        resp_hdr:
        akam_val:
        curl_conn_data:
        ssl_hs_data:
        conn_data:
        ssl_hs_raw:
        """
        self.log = {'client': '', 'srv': '', 'info': ''}
        self.d = {'client': defaultdict(dict),
             'srv': defaultdict(dict),
             'ssl': defaultdict(dict)}
        self.command = ''
        self.req_hdr = defaultdict(list)
        self.resp_hdr = defaultdict(list)
        self.akam_val = {}
        self.curl_conn_data = {}
        self.ssl_hs_data = []
        self.conn_data = []
        self.ssl_hs_raw = []
        self.ts = None
        options = self.curl_default_options
        if custom_hdr:
            options = options + custom_hdr
        command = 'curl {}'.format(hostname)
        command += options
        self.command = command

    def run(self):
        self.get_url()
        self.parse_log()
        self.parse_out()
        self.clean_conn_data()
        
    def get_url(self):
        self.ts = datetime.utcnow().strftime('%s')
        result = run_command(self.command)
        self.out = result[0]
        self.lograw = result[1]

    def parse_out(self):
        res = self.out.split(':')
        #From options
        c = {}
        c['tput_Mbps'] = float(res[1])*8/(10**6)
        #https://blog.cloudflare.com/a-question-of-timing/
        #namelookup is dns time
        c['dns'] = floor(float(res[2])*1000)
        #tcp = time_connect - time_namelookup (time to receive SYN-ACK)
        c['tcp'] = floor(float(res[3])*1000)-floor(float(res[2])*1000)
        #ssl = time_appconnect - time_connect (to complete SSL HS)
        c['ssl'] = floor(float(res[4])*1000)-floor(float(res[3])*1000)
        #req = time_pretransfer - time_appconnect (to start sending headers)
        c['req'] = floor(float(res[5])*1000) - floor(float(res[4])*1000)
        #hdr_sent->first_byte_resp; tat = time_starttransfer - time_pretransfer
        c['tat'] = floor(float(res[6])*1000) - floor(float(res[5])*1000)
        #first_byte->last_byte; xf = time_total - time_starttransfer
        c['xf'] = floor(float(res[7])*1000) - floor(float(res[6])*1000)
        self.curl_conn_data = c
        
    def parse_log(self):
        #Run through each line in the logs
        # And based on the start character, use appropriate parse function
        lines = iter(self.lograw.split('\n'))
        for line in lines:
            #Split time and rest
            try:
                time = line.split()[0]
            except IndexError:
                pass
            line = ' '.join(line.split()[1:])
            if line.startswith('>'):
                self.parse_req_hdr(line)
                self.log['client'] += line + '\n'
            elif line.startswith('<'):
                self.parse_resp_hdr(line)
                self.log['srv'] += line + '\n'              
            elif line.startswith('*'):
                if line.startswith('* TLS'):
                    self.parse_sslhs([line, next(lines, None)], time)
                else:
                    self.parse_info_hdr(line, time)
                    self.log['info'] += line + '\n'

    def parse_req_hdr(self, line):
        d={}
        line = line[1:].strip() #Ignore the start character
        #Ignore empty lines
        if not line:
            return None #Also a no body request
        #Parse the lines with name: value
        if ':' in line:
            name, _, value = line.partition(':')
            name = name.strip()
            value = value.strip()
            self.req_hdr[name].append(value) #to handle duplicate header responses
        elif 'HTTP' in line: #The HTTP request line
            value = clean_split(line)
            d['method'] = value[0]
            d['path'] = value[1]
            d['version'] = value[2]
        self.d['client']['http'].update(d)
    
    def parse_resp_hdr(self, line):
        d={}
        line = line[1:].strip() #Ignore the start character
        #Ignore empty lines
        if not line:
            return None
        #Parse the lines with name: value
        if ':' in line:
            name, _, value = line.partition(':')
            name = name.strip()
            value = value.strip()
            self.resp_hdr[name].append(value) #to handle duplicate header responses
        elif 'HTTP' in line: #The HTTP request line
            value = clean_split(line)
            d['version'] = value[0]
            d['code'] = value[1]
        self.d['srv']['http'].update(d)        

    def parse_info_hdr(self, line, time=None):
        line = line[1:].strip() #Ignore the start character
        if 'Connected' in line:
            line = clean_split(line)
            self.d['srv']['ip'] = line[3][1:-1]
            self.d['srv']['port'] = line[-2]
            self.d['client']['curl_connection'] = line[-1][1:-1]
            self.conn_data.append(['connect', time])
        elif 'SSL connection' in line:
            line = clean_split(line)
            self.d['ssl']['proto'] = line[3]
            self.d['ssl']['cipher'] = line[5]

    def parse_sslhs(self, lines, time):
        stage = ' '.join(lines[0].split()[5:])
        #Record the time of completion of sending data OR receiving data
        self.ssl_hs_data.append([stage, lines[1].split()[0]])
        self.ssl_hs_raw.append([time, lines])

    def clean_conn_data(self):
        #connect time is recorded as time from parse_info_hdr, that is the ref point
        # Use that to find the time to send client_hello
        time_diff_to_connect = datetime.strptime(self.ssl_hs_data[0][1], '%H:%M:%S.%f') - \
                               datetime.strptime(self.conn_data[0][1], '%H:%M:%S.%f')
        time_diff_ms = time_diff_to_connect.microseconds/1000
        self.conn_data.append([self.ssl_hs_data[0][0], time_diff_ms])
        #Calculate the time diff on others the same way
        # now-prev
        for n, i in enumerate(self.ssl_hs_data[1:], 1):
            prev_time = datetime.strptime(self.ssl_hs_data[n-1][1], '%H:%M:%S.%f')            
            now_time = datetime.strptime(i[1], '%H:%M:%S.%f')
            self.conn_data.append([i[0], (now_time-prev_time).microseconds/1000])
