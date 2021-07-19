import datetime
import re
#from util import run_command
import json

class MTR(object):
    """
    Parses results of MTR into a dictionary.
    If a custom mtr_command is passed, it needs to produce an output same as
    `mtr --report-wide -b ... `
    """
    def __init__(self, destination=None, psize=1500, count=10, mtr_command=None):
        """
        Input:
        destination: str
           list of ip address of the destination as string

        psize: int 
           packet size value to be passed into mtr options
        
        count: int
           count of packets value to be passed into the mtr options
        """
        self.destination = destination
        self.psize = psize
        self.count = count
        self.mtr_command = mtr_command #if custom mtr command is used
        self.mtr_info = {} #To store the parsed results
        self.mtr_meta = {} #options passed to mtr, commands ...
        self.lossy_hop = None #To indicate the lossy hop

    def run(self):
        #Run the mtr
        self.run_mtr()
        self.parse_mtr()
        self.find_lossy_hop()
        self.update_mtr_loss_info()        
        return True

    def run_mtr(self):
        #Get the current timestamp
        self.timestamp = datetime.datetime.now()
        if not self.mtr_command:
            command = "mtr {} -p {} -c {} --report-wide -b -j".format(self.destination,
                                                                      self.psize,
                                                                      self.count)
        else:
            command = self.mtr_command
        self.mtr_meta['command'] = command
        result = run_command(command)
        self.mtr_raw = result[0]
        
    def parse_mtr(self, output_type='json'):
        #If mtr's json output format is used
        if output_type == 'json':
            json_data = json.loads(self.mtr_raw)['report']
            self.mtr_results = {}
            for hop in json_data['hubs']:
                self.mtr_results[hop['count']] = hop
            self.mtr_meta = json_data['mtr']
        #Otherwise parsing the mtr data (options to mtr needs to be --report-wide -b)
        else:
            self.parse(self.mtr_raw)
        
    def get_lossy_hop(self):
        """method to get the attribute of lossy_hop"""
        return self.lossy_hop

    def get_hop_details(self, hop_n):
        """method to get the details of the hop"""
        try:
            return self.mtr_results[hop_n]
        except KeyError:
            return None

    def find_lossy_hop(self):
        """Finds the lossy hop"""
        # We will assume that the trace is lossy and start with the first hop
        current_lossy_hop = 1        
        for hop in sorted(self.mtr_results.keys()):
            # check the loss of the hop, if its 0, it means all previous hops were clean
            if self.mtr_results[hop]['Loss%'] == 0:
                current_lossy_hop = hop

        # if the current_lossy_hop was recorded as the last hop
        # and if it wasn't lossy, then return None as the trace won't be lossy
        last_hop = self.mtr_results[max(self.mtr_results.keys())]
        if (current_lossy_hop == last_hop['count'] and last_hop['Loss%'] == 0):
            return None

        # the current_lossy_hop records the latest hop which had 0 loss
        # if it isn't the last hop (checked earlier), then it should be the next hop
        self.lossy_hop = current_lossy_hop + 1

    def update_mtr_loss_info(self):
        """
        method to add one more key to the dict(mtr_results) mentioning if that hop
        was lossy or not, boolean True or False
        """
        for hop in self.mtr_results.keys():
            # if the route was determined to be lossy, lets mark all hops including
            # lossy_hop and after that as lossy
            if self.lossy_hop and hop >= self.lossy_hop:
                self.mtr_results[hop].update({'is_lossy' : True})
            # otherwise its not
            else:
                self.mtr_results[hop].update({'is_lossy' : False})

    def parse(self, mtr_data):
        """
        Parse the mtr data into a dictonary where keys are hop numbers and values
        are details of the hop.
        
        Output: dict
        """

        # RE for gathering the data
        timestamp_re = re.compile('Start: ')
        source_re = re.compile('HOST: ')
        hop_re = re.compile('[ ]+[0-9]{1,2}.|-- ')
        self.mtr_results = {}
        for i in mtr_data.split('\n'):
            if timestamp_re.match(i):
                #To address the offset issue
                #2021-02-20T06:57:56+0000
                i = i[:-5]
                self.timestamp = datetime.datetime.strptime(i.replace('Start: ', ''), '%Y-%m-%dT%H:%M:%S')
            elif source_re.match(i):
                self.headers = i.replace('HOST: ', '').split()
            elif hop_re.match(i):
                hop = i.replace('.|--', '')
                hop_info = Hop(hop).get_hop_info()
                hop_n = hop_info['count']
                self.mtr_results[hop_n] = hop_info
                
class Hop(object):
    """
    Parses each line of the mtr result, used to parse and extract info for the MTR class
    """
    def __init__(self, hop_data):
        self.hop_info = {}        
        self.parse(hop_data)
        
    def parse(self, hop_data):
        parsed_hop = hop_data.split()
        self.hop_info = {'count' : int(parsed_hop[0]),
                         'Loss%' : float(parsed_hop[-7].replace('%','')),
                         'Snt' : int(parsed_hop[-6]),
                         'Last' : float(parsed_hop[-5]),
                         'Avg' : float(parsed_hop[-4]),
                         'Best' : float(parsed_hop[-3]),
                         'Wrst' : float(parsed_hop[-2]),
                         'StDev' : float(parsed_hop[-1])}
        #Consider everyting after num and before loss data as part of the hop details for ip/name
        # The IP details almost always appears as name(IP), with IP/name being optional
        # if there is none, it will be ???
        self.hop_info.update(self.get_ip_name(parsed_hop[1:-7]))

    def set_hop_info(self, key, value):
        self.hop_info[key] = value
        
    def get_hop_info(self):
        return self.hop_info

    def get_ip_name(self, data):
        #If we have only one element passed, then it is highly likely it's just IP without name
        if len(data) == 1:
            name = '-'
            ip = data[0]
        else:
            name = data[0]
            ip = data[1].strip('()')
        return {'name' : name, 'ip': ip}
                      

