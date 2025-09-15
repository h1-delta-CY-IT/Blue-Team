#!/bin/bash
# clear

scriptDir="./linux-scripts"

running=true
touch ~/Script.log
echo >~/Script.log
chmod 777 ~/Script.log
mkdir -p ~/script-backups
chmod 777 ~/script-backups
cp /etc/group ~/script-backups/
cp /etc/passwd ~/script-backups/

function uLIst_pp() {
	echo Type all user account names, with a space in between
	read -a users

	usersLength=${#users[@]}

	for ((i = 0; i < $usersLength; i++)); do
		clear
		echo ${users[${i}]}
		echo Delete ${users[${i}]}? yes or no
		read yn1
		if [ $yn1 == y* ]; then
			userdel -r ${users[${i}]}
		else
			echo Make ${users[${i}]} administrator? yes or no
			read yn2
			if [ $yn2 == y* ]; then
				gpasswd -a ${users[${i}]} sudo
				gpasswd -a ${users[${i}]} adm
				gpasswd -a ${users[${i}]} lpadmin
				gpasswd -a ${users[${i}]} sambashare
			else
				gpasswd -d ${users[${i}]} sudo
				gpasswd -d ${users[${i}]} adm
				gpasswd -d ${users[${i}]} lpadmin
				gpasswd -d ${users[${i}]} sambashare
				gpasswd -d ${users[${i}]} root
			fi

			echo Make custom password for ${users[${i}]}? yes or no
			read yn3
			if [ $yn3 == y* ]; then
				echo Password:
				read pw
				echo -e "$pw\n$pw" | passwd ${users[${i}]}
			fi
			passwd -x30 -n3 -w7 ${users[${i}]}
			usermod -L ${users[${i}]}
		fi
	done
	clear
	echo -e '\n\nPress enter to return to main menu...'
	read return
	clear
}

function addUsr_pp() {
	echo Type user account names of users you want to add, with a space in between
	read -a usersNew

	usersNewLength=${#usersNew[@]}

	for ((i = 0; i < $usersNewLength; i++)); do
		clear
		echo ${usersNew[${i}]}
		adduser ${usersNew[${i}]}
		clear
		echo Make ${usersNew[${i}]} administrator? yes or no
		read ynNew
		if [ $ynNew == y* ]; then
			gpasswd -a ${usersNew[${i}]} sudo
			gpasswd -a ${usersNew[${i}]} adm
			gpasswd -a ${usersNew[${i}]} lpadmin
			gpasswd -a ${usersNew[${i}]} sambashare
		fi

		passwd -x30 -n3 -w7 ${usersNew[${i}]}
		usermod -L ${usersNew[${i}]}
	done
	echo -e '\n\nPress enter to return to main menu...'
	read return
	clear
}

function listUsers() {
	less /etc/passwd
}

function ipv6() {
	echo Disable IPv6?
	read ipv6YN
	if [ $ipv6YN == y* ]; then
		echo -e "\n\n# Disable IPv6\nnet.ipv6.conf.all.disable_ipv6 = 1\nnet.ipv6.conf.default.disable_ipv6 = 1\nnet.ipv6.conf.lo.disable_ipv6 = 1" >>/etc/sysctl.conf
		sysctl -p >>/dev/null
	fi

	clear
	echo -e '\n\nPress enter to return to main menu...'
	read return
	clear
}

function optServices() {
	echo The script will run you through several services, you have to answer yes/y or no/n to all of them for anything to happen:
	echo Samba, FTP, SSH, Telnet, Mailserver, printing, MySQL, webserver, DNS, media-files
	echo Does this machine need Samba?
	read sambaYN
	echo Does this machine need FTP?
	read ftpYN
	echo Does this machine need SSH?
	read sshYN
	echo Does this machine need Telnet?
	read telnetYN
	echo Does this machine need Mail?
	read mailYN
	echo Does this machine need Printing?
	read printYN
	echo Does this machine need MySQL?
	read dbYN
	echo Will this machine be a Web Server?
	read httpYN
	echo Does this machine need DNS?
	read dnsYN
	echo Does this machine allow media files?
	read mediaFilesYN

	clear
	unalias -a

	clear
	usermod -L root

	clear
	chmod 640 .bash_history

	clear
	chmod 604 /etc/shadow

	clear
	ls -a /home/ >>~/Script.log

	clear
	ls -a /etc/sudoers.d >>~/Script.log

	clear
	cp /etc/rc.local ~/script-backups/
	echo >/etc/rc.local
	echo 'exit 0' >>/etc/rc.local

	clear
	apt install ufw -y -qq
	ufw enable
	ufw deny 1337

	clear
	env i='() { :;}; echo Your system is Bash vulnerable' bash -c "echo Bash vulnerability test"

	clear
	chmod 777 /etc/hosts
	cp /etc/hosts ~/script-backups/
	echo >/etc/hosts
	echo -e "127.0.0.1 localhost\n127.0.1.1 $USER\n::1 ip6-localhost ip6-loopback\nfe00::0 ip6-localnet\nff00::0 ip6-mcastprefix\nff02::1 ip6-allnodes\nff02::2 ip6-allrouters" >>/etc/hosts
	chmod 644 /etc/hosts

	clear
	chmod 777 /etc/lightdm/lightdm.conf
	cp /etc/lightdm/lightdm.conf ~/script-backups/
	echo >/etc/lightdm/lightdm.conf
	echo -e '[SeatDefaults]\nallow-guest=false\ngreeter-hide-users=true\ngreeter-show-manual-login=true' >>/etc/lightdm/lightdm.conf
	chmod 644 /etc/lightdm/lightdm.conf

	clear
	find /bin/ -name "*.sh" -type f -delete

	clear
	cp /etc/default/irqbalance ~/script-backups/
	echo >/etc/default/irqbalance
	echo -e "#Configuration for the irqbalance daemon\n\n#Should irqbalance be enabled?\nENABLED=\"0\"\n#Balance the IRQs only once?\nONESHOT=\"0\"" >>/etc/default/irqbalance

	clear
	cp /etc/sysctl.conf ~/script-backups/
	echo >/etc/sysctl.conf
	echo -e "# Controls IP packet forwarding\nnet.ipv4.ip_forward = 0\n\n# IP Spoofing protection\nnet.ipv4.conf.all.rp_filter = 1\nnet.ipv4.conf.default.rp_filter = 1\n\n# Ignore ICMP broadcast requests\nnet.ipv4.icmp_echo_ignore_broadcasts = 1\n\n# Disable source packet routing\nnet.ipv4.conf.all.accept_source_route = 0\nnet.ipv6.conf.all.accept_source_route = 0\nnet.ipv4.conf.default.accept_source_route = 0\nnet.ipv6.conf.default.accept_source_route = 0\n\n# Ignore send redirects\nnet.ipv4.conf.all.send_redirects = 0\nnet.ipv4.conf.default.send_redirects = 0\n\n# Block SYN attacks\nnet.ipv4.tcp_syncookies = 1\nnet.ipv4.tcp_max_syn_backlog = 2048\nnet.ipv4.tcp_synack_retries = 2\nnet.ipv4.tcp_syn_retries = 5\n\n# Log Martians\nnet.ipv4.conf.all.log_martians = 1\nnet.ipv4.icmp_ignore_bogus_error_responses = 1\n\n# Ignore ICMP redirects\nnet.ipv4.conf.all.accept_redirects = 0\nnet.ipv6.conf.all.accept_redirects = 0\nnet.ipv4.conf.default.accept_redirects = 0\nnet.ipv6.conf.default.accept_redirects = 0\n\n# Ignore Directed pings\nnet.ipv4.icmp_echo_ignore_all = 1\n\n# Accept Redirects? No, this is not router\nnet.ipv4.conf.all.secure_redirects = 0\n\n# Log packets with impossible addresses to kernel log? yes\nnet.ipv4.conf.default.secure_redirects = 0\n\n########## IPv6 networking start ##############\n# Number of Router Solicitations to send until assuming no routers are present.\n# This is host and not router\nnet.ipv6.conf.default.router_solicitations = 0\n\n# Accept Router Preference in RA?\nnet.ipv6.conf.default.accept_ra_rtr_pref = 0\n\n# Learn Prefix Information in Router Advertisement\nnet.ipv6.conf.default.accept_ra_pinfo = 0\n\n# Setting controls whether the system will accept Hop Limit settings from a router advertisement\nnet.ipv6.conf.default.accept_ra_defrtr = 0\n\n#router advertisements can cause the system to assign a global unicast address to an interface\nnet.ipv6.conf.default.autoconf = 0\n\n#how many neighbor solicitations to send out per address?\nnet.ipv6.conf.default.dad_transmits = 0\n\n# How many global unicast IPv6 addresses can be assigned to each interface?
    net.ipv6.conf.default.max_addresses = 1\n\n########## IPv6 networking ends ##############" >>/etc/sysctl.conf
	sysctl -p >>/dev/null

	ipv6

	clear
	if [ $sambaYN == n* ]; then
		echo "Disabling samba..."
		ufw deny netbios-ns
		ufw deny netbios-dgm
		ufw deny netbios-ssn
		ufw deny microsoft-ds
		apt purge samba -y -qq
		apt purge samba-common -y -qq
		apt purge samba-common-bin -y -qq
		apt purge samba4 -y -qq
		clear
	elif [ $sambaYN == y* ]; then
		echo "Enabling samba..."
		ufw allow netbios-ns
		ufw allow netbios-dgm
		ufw allow netbios-ssn
		ufw allow microsoft-ds
		apt install samba -y -qq
		apt install system-config-samba -y -qq
		cp /etc/samba/smb.conf ~/script-backups/
		if [ "$(grep '####### Authentication #######' /etc/samba/smb.conf)"==0 ]; then
			sed -i 's/####### Authentication #######/####### Authentication #######\nsecurity = user/g' /etc/samba/smb.conf
		fi
		sed -i 's/usershare allow guests = no/usershare allow guests = yes/g' /etc/samba/smb.conf

		echo Type all user account names, with a space in between
		read -a usersSMB
		usersSMBLength=${#usersSMB[@]}
		for ((i = 0; i < $usersSMBLength; i++)); do
			echo -e 'M@rryH@d@l1ttlel@mb\n M@rryH@d@l1ttlel@mb' | smbpasswd -a ${usersSMB[${i}]}
		done
		clear
	else
		echo Response not recognized.
	fi

	clear
	if [ $ftpYN == n* ]; then
		echo "Disabling FTP..."
		ufw deny ftp
		ufw deny sftp
		ufw deny saft
		ufw deny ftps-data
		ufw deny ftps
		apt purge vsftpd -y -qq
	elif [ $ftpYN == y* ]; then
		echo "Enabling FTP..."
		ufw allow ftp
		ufw allow sftp
		ufw allow saft
		ufw allow ftps-data
		ufw allow ftps
		cp /etc/vsftpd/vsftpd.conf ~/script-backups/
		cp /etc/vsftpd.conf ~/script-backups/
		gedit /etc/vsftpd/vsftpd.conf &
		gedit /etc/vsftpd.conf
		service vsftpd restart
	else
		echo Response not recognized.
	fi

	clear
	if [ $sshYN == n* ]; then
		echo "Disabling SSH server..."
		ufw deny ssh
		apt purge openssh-server -y -qq
	elif [ $sshYN == y* ]; then
		echo "Enabling SSH server..."
		apt install openssh-server -y -qq
		ufw allow ssh
		cp /etc/ssh/sshd_config ~/script-backups/
		echo Type all user account names, with a space in between
		read usersSSH
		echo -e "# Package generated configuration file\n# See the sshd_config(5) manpage for details\n\n# What ports, IPs and protocols we listen for\nPort 2200\n# Use these options to restrict which interfaces/protocols sshd will bind to\n#ListenAddress ::\n#ListenAddress 0.0.0.0\nProtocol 2\n# HostKeys for protocol version \nHostKey /etc/ssh/ssh_host_rsa_key\nHostKey /etc/ssh/ssh_host_dsa_key\nHostKey /etc/ssh/ssh_host_ecdsa_key\nHostKey /etc/ssh/ssh_host_ed25519_key\n#Privilege Separation is turned on for security\nUsePrivilegeSeparation yes\n\n# Lifetime and size of ephemeral version 1 server key\nKeyRegenerationInterval 3600\nServerKeyBits 1024\n\n# Logging\nSyslogFacility AUTH\nLogLevel VERBOSE\n\n# Authentication:\nLoginGraceTime 60\nPermitRootLogin no\nStrictModes yes\n\nRSAAuthentication yes\nPubkeyAuthentication yes\n#AuthorizedKeysFile	%h/.ssh/authorized_keys\n\n# Don't read the user's ~/.rhosts and ~/.shosts files\nIgnoreRhosts yes\n# For this to work you will also need host keys in /etc/ssh_known_hosts\nRhostsRSAAuthentication no\n# similar for protocol version 2\nHostbasedAuthentication no\n# Uncomment if you don't trust ~/.ssh/known_hosts for RhostsRSAAuthentication\n#IgnoreUserKnownHosts yes\n\n# To enable empty passwords, change to yes (NOT RECOMMENDED)\nPermitEmptyPasswords no\n\n# Change to yes to enable challenge-response passwords (beware issues with\n# some PAM modules and threads)\nChallengeResponseAuthentication yes\n\n# Change to no to disable tunnelled clear text passwords\nPasswordAuthentication no\n\n# Kerberos options\n#KerberosAuthentication no\n#KerberosGetAFSToken no\n#KerberosOrLocalPasswd yes\n#KerberosTicketCleanup yes\n\n# GSSAPI options\n#GSSAPIAuthentication no\n#GSSAPICleanupCredentials yes\n\nX11Forwarding no\nX11DisplayOffset 10\nPrintMotd no\nPrintLastLog no\nTCPKeepAlive yes\n#UseLogin no\n\nMaxStartups 2\n#Banner /etc/issue.net\n\n# Allow client to pass locale environment variables\nAcceptEnv LANG LC_*\n\nSubsystem sftp /usr/lib/openssh/sftp-server\n\n# Set this to 'yes' to enable PAM authentication, account processing,\n# and session processing. If this is enabled, PAM authentication will\n# be allowed through the ChallengeResponseAuthentication and\n# PasswordAuthentication.  Depending on your PAM configuration,\n# PAM authentication via ChallengeResponseAuthentication may bypass\n# the setting of \"PermitRootLogin without-password\".\n# If you just want the PAM account and session checks to run without\n# PAM authentication, then enable this but set PasswordAuthentication\n# and ChallengeResponseAuthentication to 'no'.\nUsePAM yes\n\nAllowUsers $usersSSH\nDenyUsers\nRhostsAuthentication no\nClientAliveInterval 300\nClientAliveCountMax 0\nVerifyReverseMapping yes\nAllowTcpForwarding no\nUseDNS no\nPermitUserEnvironment no" >/etc/ssh/sshd_config
		service ssh restart
		mkdir ~/.ssh
		chmod 700 ~/.ssh
		ssh-keygen -t rsa
	else
		echo Response not recognized.
	fi

	clear
	if [ $telnetYN == n* ]; then
		ufw deny telnet
		ufw deny rtelnet
		ufw deny telnets
		apt purge telnet -y -qq
		apt purge telnetd -y -qq
		apt purge inetutils-telnetd -y -qq
		apt purge telnetd-ssl -y -qq
	elif [ $telnetYN == y* ]; then
		ufw allow telnet
		ufw allow rtelnet
		ufw allow telnets
	else
		echo Response not recognized.
	fi

	clear
	if [ $mailYN == n* ]; then
		ufw deny smtp
		ufw deny pop2
		ufw deny pop3
		ufw deny imap2
		ufw deny imaps
		ufw deny pop3s
	elif [ $mailYN == y* ]; then
		ufw allow smtp
		ufw allow pop2
		ufw allow pop3
		ufw allow imap2
		ufw allow imaps
		ufw allow pop3s
	else
		echo Response not recognized.
	fi

	clear
	if [ $printYN == n* ]; then
		ufw deny ipp
		ufw deny printer
		ufw deny cups
	elif [ $printYN == y* ]; then
		ufw allow ipp
		ufw allow printer
		ufw allow cups
	else
		echo Response not recognized.
	fi

	clear
	if [ $dbYN == n* ]; then
		ufw deny ms-sql-s
		ufw deny ms-sql-m
		ufw deny mysql
		ufw deny mysql-proxy
		apt purge mysql -y -qq
		apt purge mysql-client-core-5.5 -y -qq
		apt purge mysql-client-core-5.6 -y -qq
		apt purge mysql-common-5.5 -y -qq
		apt purge mysql-common-5.6 -y -qq
		apt purge mysql-server -y -qq
		apt purge mysql-server-5.5 -y -qq
		apt purge mysql-server-5.6 -y -qq
		apt purge mysql-client-5.5 -y -qq
		apt purge mysql-client-5.6 -y -qq
		apt purge mysql-server-core-5.6 -y -qq
	elif [ $dbYN == y* ]; then
		ufw allow ms-sql-s
		ufw allow ms-sql-m
		ufw allow mysql
		ufw allow mysql-proxy
		apt install mysql-server-5.6 -y -qq
		cp /etc/my.cnf ~/script-backups/
		cp /etc/mysql/my.cnf ~/script-backups/
		cp /usr/etc/my.cnf ~/script-backups/
		cp ~/.my.cnf ~/script-backups/
		if grep -q "bind-address" "/etc/mysql/my.cnf"; then
			sed -i "s/bind-address\t\t=.*/bind-address\t\t= 127.0.0.1/g" /etc/mysql/my.cnf
		fi
		gedit /etc/my.cnf &
		gedit /etc/mysql/my.cnf &
		gedit /usr/etc/my.cnf &
		gedit ~/.my.cnf
		service mysql restart
	else
		echo Response not recognized.
	fi

	clear
	if [ $httpYN == n* ]; then
		ufw deny http
		ufw deny https
		apt purge apache2 -y -qq
		rm -r /var/www/*
	elif [ $httpYN == y* ]; then
		apt install apache2 -y -qq
		ufw allow http
		ufw allow https
		cp /etc/apache2/apache2.conf ~/script-backups/
		if [ -e /etc/apache2/apache2.conf ]; then
			echo -e '\<Directory \>\n\t AllowOverride None\n\t Order Deny,Allow\n\t Deny from all\n\<Directory \/\>\nUserDir disabled root' >>/etc/apache2/apache2.conf
		fi
		chown -R root:root /etc/apache2

	else
		echo Response not recognized.
	fi

	clear
	if [ $dnsYN == n* ]; then
		ufw deny domain
		apt purge bind9 -qq
	elif [ $dnsYN == y* ]; then
		ufw allow domain
	else
		echo Response not recognized.
	fi

	clear
	if [ $mediaFilesYN == n* ]; then
		find / -name "*.midi" -type f >>~/Script.log
		find / -name "*.mid" -type f >>~/Script.log
		find / -name "*.mod" -type f >>~/Script.log
		find / -name "*.mp3" -type f >>~/Script.log
		find / -name "*.mp2" -type f >>~/Script.log
		find / -name "*.mpa" -type f >>~/Script.log
		find / -name "*.abs" -type f >>~/Script.log
		find / -name "*.mpega" -type f >>~/Script.log
		find / -name "*.au" -type f >>~/Script.log
		find / -name "*.snd" -type f >>~/Script.log
		find / -name "*.wav" -type f >>~/Script.log
		find / -name "*.aiff" -type f >>~/Script.log
		find / -name "*.aif" -type f >>~/Script.log
		find / -name "*.sid" -type f >>~/Script.log
		find / -name "*.flac" -type f >>~/Script.log
		find / -name "*.ogg" -type f >>~/Script.log
		clear

		find / -name "*.mpeg" -type f >>~/Script.log
		find / -name "*.mpg" -type f >>~/Script.log
		find / -name "*.mpe" -type f >>~/Script.log
		find / -name "*.dl" -type f >>~/Script.log
		find / -name "*.movie" -type f >>~/Script.log
		find / -name "*.movi" -type f >>~/Script.log
		find / -name "*.mv" -type f >>~/Script.log
		find / -name "*.iff" -type f >>~/Script.log
		find / -name "*.anim5" -type f >>~/Script.log
		find / -name "*.anim3" -type f >>~/Script.log
		find / -name "*.anim7" -type f >>~/Script.log
		find / -name "*.avi" -type f >>~/Script.log
		find / -name "*.vfw" -type f >>~/Script.log
		find / -name "*.avx" -type f >>~/Script.log
		find / -name "*.fli" -type f >>~/Script.log
		find / -name "*.flc" -type f >>~/Script.log
		find / -name "*.mov" -type f >>~/Script.log
		find / -name "*.qt" -type f >>~/Script.log
		find / -name "*.spl" -type f >>~/Script.log
		find / -name "*.swf" -type f >>~/Script.log
		find / -name "*.dcr" -type f >>~/Script.log
		find / -name "*.dir" -type f >>~/Script.log
		find / -name "*.dxr" -type f >>~/Script.log
		find / -name "*.rpm" -type f >>~/Script.log
		find / -name "*.rm" -type f >>~/Script.log
		find / -name "*.smi" -type f >>~/Script.log
		find / -name "*.ra" -type f >>~/Script.log
		find / -name "*.ram" -type f >>~/Script.log
		find / -name "*.rv" -type f >>~/Script.log
		find / -name "*.wmv" -type f >>~/Script.log
		find / -name "*.asf" -type f >>~/Script.log
		find / -name "*.asx" -type f >>~/Script.log
		find / -name "*.wma" -type f >>~/Script.log
		find / -name "*.wax" -type f >>~/Script.log
		find / -name "*.wmv" -type f >>~/Script.log
		find / -name "*.wmx" -type f >>~/Script.log
		find / -name "*.3gp" -type f >>~/Script.log
		find / -name "*.mov" -type f >>~/Script.log
		find / -name "*.mp4" -type f >>~/Script.log
		find / -name "*.avi" -type f >>~/Script.log
		find / -name "*.swf" -type f >>~/Script.log
		find / -name "*.flv" -type f >>~/Script.log
		find / -name "*.m4v" -type f >>~/Script.log
		clear

		find / -name "*.tiff" -type f >>~/Script.log
		find / -name "*.tif" -type f >>~/Script.log
		find / -name "*.rs" -type f >>~/Script.log
		find / -name "*.im1" -type f >>~/Script.log
		find / -name "*.gif" -type f >>~/Script.log
		find / -name "*.jpeg" -type f >>~/Script.log
		find / -name "*.jpg" -type f >>~/Script.log
		find / -name "*.jpe" -type f >>~/Script.log
		find / -name "*.png" -type f >>~/Script.log
		find / -name "*.rgb" -type f >>~/Script.log
		find / -name "*.xwd" -type f >>~/Script.log
		find / -name "*.xpm" -type f >>~/Script.log
		find / -name "*.ppm" -type f >>~/Script.log
		find / -name "*.pbm" -type f >>~/Script.log
		find / -name "*.pgm" -type f >>~/Script.log
		find / -name "*.pcx" -type f >>~/Script.log
		find / -name "*.ico" -type f >>~/Script.log
		find / -name "*.svg" -type f >>~/Script.log
		find / -name "*.svgz" -type f >>~/Script.log
		clear
	else
		echo Response not recognized.
	fi
	echo -e '\n\nPress enter to return to main menu...'
	read return
	clear
}

function haktoolsbyby() {
	clear
	apt purge netcat -y -qq
	apt purge netcat-openbsd -y -qq
	apt purge netcat-traditional -y -qq
	apt purge ncat -y -qq
	apt purge pnetcat -y -qq
	apt purge socat -y -qq
	apt purge sock -y -qq
	apt purge socket -y -qq
	apt purge sbd -y -qq
	rm /usr/bin/nc
	clear

	apt purge john -y -qq
	apt purge john-data -y -qq
	clear

	apt purge hydra -y -qq
	apt purge hydra-gtk -y -qq
	clear

	apt purge aircrack-ng -y -qq
	clear

	apt purge fcrackzip -y -qq
	clear

	apt purge lcrack -y -qq
	clear

	apt purge ophcrack -y -qq
	apt purge ophcrack-cli -y -qq
	clear

	apt purge pdfcrack -y -qq
	clear

	apt purge pyrit -y -qq
	clear

	apt purge rarcrack -y -qq
	clear

	apt purge sipcrack -y -qq
	clear

	apt purge irpas -y -qq
	clear
	echo -e '\n\nPress enter to return to main menu...'
	read return
	clear
}

function lynis() {
	apt install lynis -y -qq
	lynis -c -Q --no-colors >~/Desktop/logs/lynis.log
	chmod 777 ~/Desktop/logs/lynis.log

	echo -e '\n\nPress enter to return to main menu...'
	read return
	clear
}

function pam() {
	apt install libpam-cracklib -y -qq
	cp /etc/pam.d/common-auth ~/script-backups/
	cp /etc/pam.d/common-password ~/script-backups/
	echo -e "#\n# /etc/pam.d/common-auth - authentication settings common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of the authentication modules that define\n# the central authentication scheme for use on the system\n# (e.g., /etc/shadow, LDAP, Kerberos, etc.).  The default is to use the\n# traditional Unix authentication mechanisms.\n#\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\nauth	[success=1 default=ignore]	pam_unix.so nullok_secure\n# here's the fallback if no module succeeds\nauth	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\nauth	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\nauth	optional			pam_cap.so \n# end of pam-auth-update config\nauth required pam_tally2.so deny=5 unlock_time=1800 onerr=fail audit even_deny_root_account silent" >/etc/pam.d/common-auth
	echo -e "#\n# /etc/pam.d/common-password - password-related modules common to all services\n#\n# This file is included from other service-specific PAM config files,\n# and should contain a list of modules that define the services to be\n# used to change user passwords.  The default is pam_unix.\n\n# Explanation of pam_unix options:\n#\n# The \"sha512\" option enables salted SHA512 passwords.  Without this option,\n# the default is Unix crypt.  Prior releases used the option \"md5\".\n#\n# The \"obscure\" option replaces the old \`OBSCURE_CHECKS_ENAB\' option in\n# login.defs.\n#\n# See the pam_unix manpage for other options.\n\n# As of pam 1.0.1-6, this file is managed by pam-auth-update by default.\n# To take advantage of this, it is recommended that you configure any\n# local modules either before or after the default block, and use\n# pam-auth-update to manage selection of other modules.  See\n# pam-auth-update(8) for details.\n\n# here are the per-package modules (the \"Primary\" block)\npassword	[success=1 default=ignore]	pam_unix.so obscure sha512\n# here's the fallback if no module succeeds\npassword	requisite			pam_deny.so\n# prime the stack with a positive return value if there isn't one already;\n# this avoids us returning an error just because nothing sets a success code\n# since the modules above will each just jump around\npassword	required			pam_permit.so\n# and here are more per-package modules (the \"Additional\" block)\npassword	optional	pam_gnome_keyring.so \n# end of pam-auth-update config" >/etc/pam.d/common-password
	echo -e '\n\nPress enter to return to main menu...'
	read return
	clear
}

function hardinfo() {
	apt install hardinfo -y -qq
	hardinfo -r >~/Desktop/logs/hardwareinfo.log
	chmod 777 ~/Desktop/logs/hardwareinfo.log

	echo -e '\n\nPress enter to return to main menu...'
	read return
	clear
}

function kill() {
	echo Type all applications to be deleted, with a space in between
	read -a purge
	apt purge ${purge} -y -qq
	echo -e '\n\nPress enter to return to main menu...'
	read return
	clear
}

function runprivacy() {
	echo "This will run an auto-generated script (check privacy-script.sh for more)"
	echo "It'll do a ton of things for privacy:"
	echo "$(
		tput setaf 1
		tput setab 7
	)Privacy Cleanup$(tput sgr 0)"
	cat <<LIST
Clear terminal history
Clear 3rd-party application cache (Wine, Thunderbird, VSCode, Azure CLI, Python, Steam, Clementine, LibreOffice)
Clear browser history (Gnome Web (Epiphany), Firefox)
Clear Zeitgeist data (activity logs)
Clear recently used files list
Clear package manager data
Clear all cache (user-specific, system-wide, Flatpak apps, Snap apps, thumbnails)
Clear trash
Clear global temporary folders
Clear screenshots
LIST
	echo "$(
		tput setaf 1
		tput setab 7
	)Disable OS Data Collection$(tput sgr 0)"
	cat <<LIST
Disable telemetry for Debian, Arch Linux, Zorin OS, Ubuntu
Disable Zeitgeist (activity logging framework)
LIST
	echo "$(
		tput setaf 1
		tput setab 7
	)Configure Programs$(tput sgr 0)"
	cat <<LIST
Disable VSCode data collection
Configure Firefox (harden privacy, disable telemetry, disable Pioneer program, disable phishing protection (it decreases security))
Disable .NET telemetry
Disable PowerShell Core telemetry
LIST
	if ! test -f $scriptDir/privacy-script.sh; then
		echo "$(tput setaf 1)Error: Privacy script not found in directory.$(tput sgr 0)"
		return
	fi
	echo "Would you like to run it? MAKE SURE IT WON'T DELETE ANYTHING CRITICAL, you should probably do the forensics questions first before trying this!"
	read privacyYN
	if [ $privacyYN == y* ]; then
		bash $scriptDir/privacy-script.sh
	fi
}

function undoprivacy() {
	if ! test -f $scriptDir/privacy-script-revert.sh; then
		echo "$(tput setaf 1)Error: Privacy revert script not found in directory.$(tput sgr 0)"
		return
	fi
	echo "This will enable everything the privacy script disables, are you sure? (It cannot restore any deleted data/cache)"
	read privacyrevertYN
	if [ $privacyrevertYN == y* ]; then
		bash $scriptDir/privacy-script-revert.sh
	fi
}

# Function to handle SIGINT (Ctrl+C) interrupt
handle_interrupt() {
	echo "DEBUG here is script.log!!!"
	cat ~/Script.log
	# Put any cleanup or other commands you want to run here.
	exit 1
}

# Trap SIGINT and call handle_interrupt function
trap 'handle_interrupt' SIGINT

while [ "$running" = true ]; do
	cat <<MENU
What do you want to do? Type the keyword and hit enter (Type "exit" or "quit" to exit the script):
user: User management
adduser: Add users
listuser: List users
ipv6: Enable/disable IPv6
services: Enable/disable optional services
hacking: Remove hacking tools
kill: Kill programs
lynis: Run Lynis (security auditing tool)
pam: Setup PAM (password security)
hardinfo: Run HardInfo (check hardware information)
privacy: Run privacy script
undoprivacy: Undo privacy script
shell: Drop into sh shell
MENU
	read answer
	clear

	if [ $answer == "user" ]; then
		uLIst_pp
		# clear
	fi

	if [ $answer == "adduser" ]; then
		addUsr_pp
		# clear
	fi

	if [ $answer == "listusers" ]; then
		listUsers
		# clear
	fi

	if [ $answer == "ipv6" ]; then
		ipv6
		# clear
	fi

	if [ $answer == "services" ]; then
		optServices
		# clear
	fi

	if [ $answer == "hacking" ]; then
		haktoolsbyby
		# clear
	fi

	if [ $answer == "kill" ]; then
		kill
		# clear
	fi

	if [ $answer == "lynis" ]; then
		lynis
		apt purge lynis -y -qq
		# clear
	fi

	if [ $answer == "pam" ]; then
		pam
		# clear
	fi

	if [ $answer == "hardinfo" ]; then
		hardinfo
		apt purge hardinfo -y -qq
		# clear
	fi

	if [ $answer == "privacy" ]; then
		runprivacy
	fi

	if [ $answer == "undoprivacy" ]; then
		undoprivacy
	fi

	if [ $answer == "shell" ]; then
		/bin/sh
	fi

	if [ $answer == quit ] || [ $answer == exit ] || [ $answer == ^C ]; then
		running=false
	fi
done
