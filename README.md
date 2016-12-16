# cis667_finalproject
Final Project for CIS667 - Packet Analyzer Neural Net
Kevin Allison, kralliso@syr.edu

Requirements:
Python 2.7
Theano and Keras Frameworks/Toolkits

To generate training data:
./packet.py <filename> <malicious|safe> <outputfile>
or
python packet.py <filename> <malicious|safe> <outputfile>

Running the main program:
./project.py
or
python project.py

* Always select the first option (1. Train Neural Net) upon starting, the net must be trained!
Pick from other options as needed.  

Examples:
./packet.py data/synflood-1.pcap malicious train-2.csv
./packet.py data/SynFlood.pcap malicious train-2.csv
./packet.py data/icmp-regular.pcap safe train-2.csv
./packet.py data/icmp-dos.pcap malicious train-2.csv
./packet.py data/icmp-pingofdeath.pcap malicious train-2.csv
./packet.py data/traffic-1.pcap safe train-2.csv

./project.py 
-> 1. Train Neural Net
-> 2. Evaluate Neural Net
  -> data/web-regular.pcap
-> 4. Exit
