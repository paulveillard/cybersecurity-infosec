#!/bin/bash
# NMAP Scan + XML SearchSploit Information
#version 
if [ $# -ne 1 ]
  then
    echo "NMAP Enumeration Script V2"
    echo "Usage nmapv2.sh <target>"
    exit
fi
mkdir ./$1/
echo '[*] Running version scan.'
nmap -sV --version-all -p- -oX ./$1/version-scan-xml.xml $1 | tee ./$1/version-scan.txt

#tcp
echo '[*] Running TCP scan.'
nmap -Pn -A -sC -sS -T 4 -p- $1 | tee ./$1/tcp-scan.txt

#aggressive/service
echo '[*] Running aggressive service scan.'
nmap -A $1 | nmap -sC $1 | tee ./$1/aggressive-service.txt

#udp
echo '[*] Running UDP scan.'
nmap -Pn -A -sC -sU -T 4 --top-ports 500 $1 | tee ./$1/udp-500.txt

#SearchSploit
searchsploit -w --nmap ./$1/version-scan-xml.xml
