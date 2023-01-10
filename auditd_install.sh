#!/bin/bash


#Set executable on filtr.py
# Ustaw plik filtr.py jako uruchamialny
chmod +x filtr.py

# Install service
# Instlacja auditd na hoscie
yum -y install audit
systemctl enable auditd.service
#Add rules to auditd
#Dodanie regul

file_conf=/etc/audit/rules.d/audit.rules
touch $file_conf
if [ -e "$file_conf" ] ; then
	echo -e "-a always,exit -F arch=b32 -S execve -k execv" >$file_conf
	echo -e "-a always,exit -F arch=b64 -S execve -k execv" >>$file_conf
	echo -e "-w /etc/passwd -p war -k watch_passwd" >>$file_conf
	echo -e "-w /etc/shadow -p war -k watch_shadow" >>$file_conf
	echo -e "-w /etc - p wa -k watch_etc" >>$file_conf
else
	echo "No config file"
fi


#Install python3
yum -y install python36 
yum -y install python3-pip
pip3 install --no-index --find-links . sh



# Restart service
service auditd restart
#service auditd status
#Rules count
cat /etc/audit/audit.rules 

#Copy scrypt to system
cp ./filtr.py /usr/bin/filtr.py

#Install service startfiltr
touch /lib/systemd/system/startfiltr.service
sfile=/lib/systemd/system/startfiltr.service
echo -e "[Unit]">$sfile
echo -e "Description=Auditd_filtr_start">>$sfile
echo -e "">>$sfile
echo -e "[Service]">>$sfile
echo -e "ExecStart=/usr/bin/filtr.py">>$sfile
echo -e "">>$sfile
echo -e "[Install]">>$sfile
echo -e "WantedBy=default.target">>$sfile


#Reload demons
systemctl daemon-reload

#Start service 
service startfiltr start
#Status service
service startfiltr status
#Add service to start on boot system
systemctl enable startfiltr.service

#Create log rotate config

touch /etc/logrotate.d/audit_logger
lfile=/etc/logrotate.d/audit_logger
echo -e "/var/log/audit_commands.log {" > $lfile
echo -e "    size 50M">>$lfile
echo -e "    monthly">>$lfile
echo -e "    create">>$lfile
echo -e "    rotate 4">>$lfile
echo -e "    compress">>$lfile
echo -e "    missingok">>$lfile
echo -e "    postrotate">>$lfile
echo -e "        /usr/bin/systemctl try-restart startfiltr.service">>$lfile
echo -e "    endscript" >>$lfile
echo -e "}" >>$lfile
