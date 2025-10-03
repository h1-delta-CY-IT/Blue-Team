#!/bin/bash
old="IHPLRulez!"
current=$(pwgen -s -1 50)
olname="plinktern"
newname="gelatinoushorse"
echo $current


for ip in "172.16.x.5" "172.16.x.10" "172.16.x.20" "172.16.x.30" "172.16.x.40"; do
	sshpass -p $old ssh $olname@$ip "spawn sudo su \n expect 'Password:' send '$old\r' adduser $newname && echo "$newname:$current" | chpasswd && usermod -aG sudo $newname && deluser $olname"

done
sudo su
//echo -e "$current\ncurrent" | passwd "$newname"


while True; do
	for ip in "172.16.x.5" "172.16.x.10" "172.16.x.20" "172.16.x.30" "172.16.x.40"; do
		sshpass -p $current ssh $newname@$ip
	done
	
done
