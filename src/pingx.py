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
        command = 'ping -c {} {}'.format(self.count, self.source)
        result = run_command(command)
        self.ping_raw = result[0]

    def parse_output(self):
        times = []
        for line in self.ping_raw.split('\n'):
            #100 packets transmitted, 59 packets received, +2 duplicates, 41.0% packet loss
            if 'packets transmitted' in line:
                info = line.split()
                sent = int(info[0])
                recv = int(info[3])
                loss = round(float((sent-recv)/sent), 2)
            #round-trip min/avg/max/stddev = 46.942/89.985/244.588/41.762 ms
            elif 'round-trip' in line:
                info = line.split()
                stats = info[3].split('/')
                rtt_min = float(stats[0])
                rtt_avg = float(stats[1])
                rtt_max = float(stats[2])
                rtt_stddev = float(stats[3])
            #To Handle these lines
            # 64 bytes from 1.1.1.1: icmp_seq=40 ttl=253 time=95.450 ms
            # 64 bytes from 1.1.1.1: icmp_seq=40 ttl=253 time=98.275 ms (DUP!)
            # 64 bytes from 1.1.1.1: icmp_seq=41 ttl=253 time=96.287 ms
            elif 'bytes from' in line and '(DUP!)' not in line:
                time = line.split()[-2].split('=')[-1]
                times.append(time)
        self.ping_results = {'sent': sent,
                             'recv': recv,
                             'loss': loss,
                             'min': rtt_min,
                             'avg': rtt_avg,
                             'max': rtt_avg,
                             'stddev': rtt_stddev,
                             'times': times}

