#!/bin/bash
if [ $# -ne 3 ]
  then
    echo "HTTP Enumeration Script V2"
    echo "Usage httpenum.sh <target> <port> <DirSearch Extension Module (e.g PHP, ASP, ALL)>"
    exit
fi

echo "Running DirSearch..."
python3 /root/Desktop/dirsearch-master/dirsearch.py -u http://$1:$2 -e $3 --plain-text-report=./$1/dirsearch-report.txt --random-agents | tee

echo "Running NMap HTTP Enumeration"
nmap --script=http-enum $1 | tee -a ./$1/http-enum.txt 

echo "Running Nikto Vulnerability Assessment"
nikto -h http://$1:$2 | tee -a ./$1/nikto.txt 

echo "Running NMap HTTP Vuln Assessment"
nmap --script=http-vuln* $1 | tee -a ./$1/http-vuln.txt
