__version__ = 1.2
__author__ = 'Abdul El-Assaad'

import sys
import ipaddress
import re
import argparse

# Regex patterns for all possible Cisco ASA line combinations
regex_patterns = [
    r'access-list (?P<acl_name>.*) line (?P<acl_no>\d+) extended (?P<acl_action>\w+) (?P<acl_proto>\w+) (?P<src_subnet>\d+.\d+.\d+.\d+) (?P<src_mask>\d+.\d+.\d+.\d+) (?P<dst_subnet>\d+.\d+.\d+.\d+) (?P<dst_mask>\d+.\d+.\d+.\d+)((?:\seq\s(?P<dst_port>\w+-\w+|\w+))|(?:\srange\s(?P<dst_port_range>\w+ \w+)))?',
    r'access-list (?P<acl_name>.*) line (?P<acl_no>\d+) extended (?P<acl_action>\w+) (?P<acl_proto>\w+) (?P<src_subnet>\d+.\d+.\d+.\d+) (?P<src_mask>\d+.\d+.\d+.\d+) host (?P<dst_host>\d+.\d+.\d+.\d+)((?:\seq\s(?P<dst_port>\w+-\w+|\w+))|(?:\srange\s(?P<dst_port_range>\w+ \w+)))?',
    r'access-list (?P<acl_name>.*) line (?P<acl_no>\d+) extended (?P<acl_action>\w+) (?P<acl_proto>\w+) (?P<src_subnet>\d+.\d+.\d+.\d+) (?P<src_mask>\d+.\d+.\d+.\d+) (?P<dst_ip>any)((?:\seq\s(?P<dst_port>\w+-\w+|\w+))|(?:\srange\s(?P<dst_port_range>\w+ \w+)))?',

    r'access-list (?P<acl_name>.*) line (?P<acl_no>\d+) extended (?P<acl_action>\w+) (?P<acl_proto>\w+) host (?P<src_ip>\d+.\d+.\d+.\d+) host (?P<dst_ip>\d+.\d+.\d+.\d+)((?:\seq\s(?P<dst_port>\w+-\w+|\w+))|(?:\srange\s(?P<dst_port_range>\w+ \w+)))?',
    r'access-list (?P<acl_name>.*) line (?P<acl_no>\d+) extended (?P<acl_action>\w+) (?P<acl_proto>\w+) host (?P<src_ip>\d+.\d+.\d+.\d+) (?P<dst_subnet>\d+.\d+.\d+.\d+) (?P<dst_mask>\d+.\d+.\d+.\d+)((?:\seq\s(?P<dst_port>\w+-\w+|\w+))|(?:\srange\s(?P<dst_port_range>\w+ \w+)))?',
    r'access-list (?P<acl_name>.*) line (?P<acl_no>\d+) extended (?P<acl_action>\w+) (?P<acl_proto>\w+) host (?P<src_ip>\d+.\d+.\d+.\d+) (?P<dst_ip>any)((?:\seq\s(?P<dst_port>\w+-\w+|\w+))|(?:\srange\s(?P<dst_port_range>\w+ \w+)))?',

    r'access-list (?P<acl_name>.*) line (?P<acl_no>\d+) extended (?P<acl_action>\w+) (?P<acl_proto>\w+) (?P<src_ip>any) host (?P<dst_ip>\d+.\d+.\d+.\d+)((?:\seq\s(?P<dst_port>\w+-\w+|\w+))|(?:\srange\s(?P<dst_port_range>\w+ \w+)))?',
    r'access-list (?P<acl_name>.*) line (?P<acl_no>\d+) extended (?P<acl_action>\w+) (?P<acl_proto>\w+) (?P<src_ip>any) (?P<dst_subnet>\d+.\d+.\d+.\d+) (?P<dst_mask>\d+.\d+.\d+.\d+)((?:\seq\s(?P<dst_port>\w+-\w+|\w+))|(?:\srange\s(?P<dst_port_range>\w+ \w+)))?',
    r'access-list (?P<acl_name>.*) line (?P<acl_no>\d+) extended (?P<acl_action>\w+) (?P<acl_proto>\w+) (?P<src_ip>any) (?P<dst_ip>any)((?:\seq\s(?P<dst_port>\w+-\w+|\w+))|(?:\srange\s(?P<dst_port_range>\w+ \w+)))?',
]

class FirewallDatabase(object):
    def __init__(self):
        self.rules = {}
        self.matches = {}
        self.read_rules_from_file()
        self.get_match_results()
        self.show_match_results()
        self.save_match_results()


    def read_rules_from_file(self):
        # Try and open the rule file and read all the contents to memory
        try:
            with open (args["file"]) as file:
                file_output = file.read().split("\n")
        except IOError:
            print ("Unable to read the firewall rules from: '{}'".format(args["file"]))
            sys.exit(0)
        # compare each line against possible regex patterns and store the matches in the rules dictionary
        for pattern in regex_patterns:
            for line in file_output:
                if "access-list" not in line:
                    continue
                match = re.search(pattern, line)
                if match:
                    self.add_rule(match)


    def add_rule(self, rule):
        
        # add a new entry to the dictionary based on the acl name+no; pre-populate fields based on regex group names
        entry = rule.groupdict(0)['acl_name'] + '-' + rule.groupdict(0)['acl_no']
        self.rules[entry] = rule.groupdict()
        
        # store raw acl in a dedicated dictionary key
        self.rules[entry]['raw'] = rule.group(0)

        # change value type to string to avoid breaking logic down the track
        if "dst_port" in self.rules[entry] and self.rules[entry]["dst_port"] == None:
            self.rules[entry]["dst_port"] = ""
        if "dst_port_range" in self.rules[entry] and self.rules[entry]["dst_port_range"] == None:
            self.rules[entry]["dst_port_range"] = ""


    # methods used to search for specific match criteria

    def find_exact_phrase(self, exact_phrase):
        return re.compile(r'^\b({0})$\b'.format(exact_phrase),flags=re.IGNORECASE).search

    def ip_exist_in_subnet(self, ip, subnet, subnet_mask):
        network = subnet + "/" + subnet_mask
        if ipaddress.ip_address(ip) in ipaddress.ip_network(network):
            return True
        return False

    def check_port_in_range(self, port, range_start, range_end):
        try:
            if int(range_start) <= int(port) <= int(range_end):
                return True
        except:
            return False

    def check_rule_for_protocol_match(self, rule, protocol):
        if "deny" in rule["acl_action"]:
            return False
        elif "any" in protocol:
            return True
        elif "any" in rule["acl_proto"]:
            return True
        elif protocol in rule["acl_proto"]:
            return True

    def check_rule_for_srcip_match(self, rule, src_ip):
        if "deny" in rule["acl_action"]:
            return False
        elif "any" in src_ip:
            return True
        elif "src_ip" in rule and "any" in rule["src_ip"]:
            return True
        elif "src_subnet" in rule and self.ip_exist_in_subnet(src_ip, rule["src_subnet"], rule["src_mask"]):
            return True
        elif "src_ip" in rule and src_ip in rule["src_ip"]:
            return True

    def check_rule_for_dstip_match(self, rule, dst_ip):
        if "deny" in rule["acl_action"]:
            return False
        elif "any" in dst_ip:
            return True
        elif "dst_ip" in rule and "any" in rule["dst_ip"]:
            return True
        elif "dst_ip" in rule and dst_ip in rule["dst_ip"]:
            return True
        elif "dst_subnet" in rule and self.ip_exist_in_subnet(dst_ip, rule["dst_subnet"], rule["dst_mask"]):
            return True

    def check_rule_for_dstport_match(self, rule, dst_port):
        if "deny" in rule["acl_action"]:
            return False
        elif "any" in dst_port:
            return True
        elif "dst_port" in rule and self.find_exact_phrase(dst_port)(rule["dst_port"]):
            return True
        elif "dst_port_range" in rule and rule["dst_port_range"]:
            range_start, range_end = rule["dst_port_range"].split(" ")
            if self.check_port_in_range(dst_port,range_start,range_end):
                return True
        elif "dst_ip" in rule and "any" in rule["dst_ip"] and not rule["dst_port"]:
            return True
            
    def rule_meets_user_match_conditions(self, rule):
        src_found = self.check_rule_for_srcip_match(rule, args["src_ip"])
        dst_found = self.check_rule_for_dstip_match(rule, args["dst_ip"])
        dst_port_found = self.check_rule_for_dstport_match(rule, args["dst_port"])
        protocol_found = self.check_rule_for_protocol_match(rule, args["proto"])

        if protocol_found and src_found and dst_found and dst_port_found:
            return True


    def get_match_results(self):
        for rule in self.rules:
            current = self.rules[rule]

            if self.rule_meets_user_match_conditions(current):
                self.matches[rule] = current

    # methods to display and save results

    def show_match_results(self):
        print ("")
        print ("==========================================")
        print ("Running Cisco ASA Rule Checker {}: ".format(__version__))
        print ("==========================================")
        print ("Reading Rules From:     '{}'".format(args["file"]))
        print ("Searching for PROTOCOL: '{}'".format(args["proto"]))
        print ("Searching for SRC IP:   '{}'".format(args["src_ip"]))
        print ("Searching for DST IP:   '{}'".format(args["dst_ip"]))
        print ("Searching for DST PORT: '{}'".format(args["dst_port"]))

        if self.matches:
            print ("")
            print ("==========================================")
            print ("The following matches have been found:    ")
            print ("==========================================")
            for match in sorted(self.matches):
                print ("MATCH: {}".format(self.matches[match]['raw']))        
        else:
            print ("")
            print ("===============================")
            print ("No Results Found              ")
            print ("===============================")

        print ("\nOutput saved to 'matches.txt'")
        self.save_match_results()


    def save_match_results(self):
        import time
        capture_time = time.asctime( time.localtime(time.time()))
        with open("matches.txt","w") as f:
            print ("==========================================", file=f)
            print ("Running Cisco ASA Rule Checker {} @ {}: ".format(__version__, capture_time), file=f)
            print ("==========================================", file=f)
            print ("Reading Rules From:     '{}'".format(args["file"]), file=f)
            print ("Searching for PROTOCOL: '{}'".format(args["proto"]), file=f)
            print ("Searching for SRC IP:   '{}'".format(args["src_ip"]), file=f)
            print ("Searching for DST IP:   '{}'".format(args["dst_ip"]), file=f)
            print ("Searching for DST PORT: '{}'".format(args["dst_port"]), file=f)
            if self.matches:
                print ("", file=f)
                print ("==========================================", file=f)
                print ("The following matches have been found:    ", file=f)
                print ("==========================================", file=f)
                for match in sorted(self.matches):
                    print ("MATCH: {}".format(self.matches[match]['raw']), file=f)           
            else:
                print ("", file=f)
                print ("===============================", file=f)
                print ("No Results Found               ", file=f)
                print ("===============================", file=f)



def show_instructions():
    print ("=====================")
    print (" Instructions")
    print ("=====================")
    print ("1. Issue the show access-list command on a Cisco ASA firewall and dump the output into a text file.")
    print ("2. Run the script using python checkrules.py -file <name of the file>")
    print ("3. Optional arguments including: ")
    print ("")
    print ("  -proto <tcp|udp|icmp|any>")
    print ("  -src_ip <ip address|any>")
    print ("  -dst_ip <ip address|any>")
    print ("  -dst_port <port_no|port_name|any>")
    
    print (" ")
    print ("Note 1. More than one argument can be entered.")
    print ("Note 2. If no arguments are entered, all entries will be shown.")
    print ("Note 3. ~7 seconds processing time per 200k entries")
    print (" ")

# -------------------
# start the script
# -------------------

if __name__ == '__main__':
    show_instructions()
    parser = argparse.ArgumentParser(description='Cisco ASA Rule Checker {}'.format(__version__))
    parser.add_argument('-file',     help='Specify the name of the file which contains the rules', required=True)
    parser.add_argument('-src_ip',   help='Specify the SRC IP to search for (x.x.x.x or any)', default="any", required=False)
    parser.add_argument('-dst_ip',   help='Specify the DST IP to search for (x.x.x.x or any)', default="any", required=False)
    parser.add_argument('-proto',    help='Specify the protocol to search for (tcp,udp,icmp or any)', default="any", required=False)
    parser.add_argument('-dst_port', help='Specify the destination port to search for', default="any", required=False)
    args = vars(parser.parse_args())
    db = FirewallDatabase()
