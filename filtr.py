#!/usr/bin/python3

from sh import tail
from datetime import datetime
import re
import socket
import time


UDP_IP = "127.0.0.1" #changeme (send to remote server)
UDP_PORT = 5555 #changeme (send to remote server)
logfile = '/var/log/audit_commands.log'


time.sleep(10)
lastRecord=False
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
hostname = socket.gethostname()



def callback(m):
	try:
		m = m.group(0)
		m = m[1:]
		return '='+m.decode('hex')
	except:
		return '='+m


for line in tail("-F", "/var/log/audit/audit.log", _iter=True):
	if lastRecord:
		if "type=EXECVE" in line:
			_,msg=line.strip().split('msg=')
			aid,exe = msg.split(": ",1)
			time, id = aid.split(":",1)
			time = int(time[6:16])
			time = datetime.fromtimestamp(time).strftime("%Y-%m-%d %H:%M:%S")
			exe = exe.split(" ",1)[1]
			exe = re.sub(r'=[0-9A-F]{5,}',callback,exe)
			exe = re.sub(r'a[0-9]=', '',exe)
			exe = re.sub(r'"', '',exe)
			log_entry="timestamp='"+time+"'"+" "+"address='"+hostname+"'"+" "+"comm='"+exe+"'"+"\n"
			#sock.sendto(bytes(log_entry, "utf-8"), (UDP_IP, UDP_PORT)) #uncomment if you set ip/port
			try:
				log_file = open(logfile, 'a')
				log_file.write(log_entry)
				log_file.close()
			except FileNotFoundError:
				pass

	if "type=SYSCALL" and "tty=pts" not in line:
		lastRecord=False
		continue
	lastRecord=True
	_,msg=line.strip().split('msg=')
	aid,exe = msg.split(": ",1)
	time, id = aid.split(":",1)
	time = int(time[6:16])
	time = datetime.fromtimestamp(time).strftime("%Y-%m-%d %H:%M:%S")
	logTable = line.split(' ')
	success=logTable[4]
	comm=logTable[24]
	auid=logTable[29]
	euid=logTable[32]
	log_entry="timestamp='"+time+"'"+" "+"address='"+hostname+"'"+" "+comm+" "+success+" "+auid+" "+euid+"\n"
	#sock.sendto(bytes(log_entry, "utf-8"), (UDP_IP, UDP_PORT))  #uncomment if you set ip/port
	try:
		log_file = open(logfile, 'a')
		log_file.write(log_entry)
		log_file.close()
	except FileNotFoundError:
		pass



