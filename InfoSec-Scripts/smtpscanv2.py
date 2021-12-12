#!/usr/bin/python
# Basic socket code taken from OSCP with credit, 
# automation and other features added by James Hemmings.
# SMTP Enumeration Tool (Usernames)
import socket
import sys
# Open File
with open('/usr/share/wordlists/metasploit/unix_users.txt', 'r') as users:

	data = users.read().splitlines()
try:
  sys.argv[1]
except:
  print "Usage: smtpscanv2.py <ip address>"
  sys.exit()

ip = sys.argv[1]
port = 25
print "[*] SMTP VRFY User Enumeration Tool"
#Loop through data and insert users into username index
for username in range(len(data)):
	print "[*] Enumerating " + data[username]
	# Create a Socket
	s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	# Connect to the Server
	connect=s.connect((ip,port))
	# Receive the banner
	banner=s.recv(1024)
	print banner
	# VRFY a user using username from index
	s.send ('EHLO examlab.offsec.local' + '\r\n')
	s.send('VRFY ' + data[username] + '\r\n')
	result=s.recv(1024)
	print result
	#Close the socket
	s.close()
