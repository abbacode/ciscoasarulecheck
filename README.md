# ciscoasarulecheck
Python script that allows offline parsing of Cisco ASA firewall rules

==========================
Features of the script:
==========================
* Allows offline parsing of firewall rules to determine whether traffic is permitted between two hosts
* Will automatically search 'subnets' to determine whether the host falls into that network range
* Will automatically search for a specific destination port if a range of ports is in use
* Optional: the use of the 'any' keyword for search paramaters

====================
Installation notes
====================
Tested using Windows 8.1 64-bit and 32-bit running Python 3.4.2

Requirements:
* No external dependencies required

=========================
Operating instructions:
=========================
* Extract the contents of the zip file into a directory
* Capture the output of the 'show access-list' command place it into the same directory as the script
* Run the script

* Some common execution examples are as follows:
 - python rulecheck.py -file rules.txt -src_ip 192.168.1.10 -dst_ip 172.1.1.1
 - python rulecheck.py -file rules.txt -src_ip 192.168.1.10 -dst_ip 172.1.1.1 -dst_port 22
 - python rulecheck.py -file rules.txt -src_ip 192.168.1.10 -dst_ip 172.1.1.1 -dst_port ssh
 - python rulecheck.py -file rules.txt -src_ip any -dst_ip any 
 - python rulecheck.py -file rules.txt -src_ip any -dst_ip any -dst_port 22
 - python rulecheck.py -file rules.txt -src_ip any -dst_ip any -dst_port ssh
 - python rulecheck.py -file rules.txt -src_ip any -dst_ip any -dst_port 22 -proto tcp
 - python rulecheck.py -file rules.txt -src_ip any -dst_ip any -dst_port 53 -proto udp
