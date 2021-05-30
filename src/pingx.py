from util import run_command

class Ping(object):
    def __init__(self, source, count=10):
        self.source = source
        self.count = count
        self.ping_results = {}

    def run(self):
        self.run_ping()
        self.parse_output()

    def run_ping(self):
        command = 'ping -q -c {} {}'.format(self.count, self.source)
        result = run_command(command)
        self.ping_raw = result[0]

    def parse_output(self):
        for line in self.ping_raw.split('\n'):
            if 'packets transmitted' in line:
                info = line.split()
                sent = int(info[0])
                recv = int(info[3])
                loss = round(float((sent-recv)/sent), 2)
            elif 'round-trip' in line:
                info = line.split()
                stats = info[3].split('/')
                rtt_min = float(stats[0])
                rtt_avg = float(stats[1])
                rtt_max = float(stats[2])
                rtt_stddev = float(stats[3])
        self.ping_results = {'sent': sent,
                             'recv': recv,
                             'loss': loss,
                             'min': rtt_min,
                             'avg': rtt_avg,
                             'max': rtt_avg,
                             'stddev': rtt_stddev}

