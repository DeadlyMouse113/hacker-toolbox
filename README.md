# hacker-toolbox
A more personal list with webapplications, command-line tools and common applications used in the hacking industry.
Some tools can be used in multiple areas or are multi-purpose.

* TryHackMe: https://tryhackme.com/signup?referrer=61ffc6b4ed7ff300494e5c8b
* HackTheBox: https://referral.hackthebox.com/mz8sr3Y

# RECONNAISSANCE & OSINT
* Google Fu (google is your best friend to find answers)
* Maltego (https://www.kali.org/tools/maltego/)

## Image OSINT
* https://jimpl.com/ (EXIF Data)
* https://lens.google.com
* https://yandex.com
* https://tineye.com
* https://pimeyes.com (paid)

## Email OSINT
### Find Emails
* Hunter - https://Hunter.io(https://Hunter.io)
* Phonebook - https://Phonebook.cz
* VoilaNorbert - https://Voilanorbert.com
* Clearbit Connect (chrome extension) 
* TheHarvester - (https://www.kali.org/tools/theharvester)
  
### Verify Emails
* Email Hippo - https://tools.emailhippo.com/
* Email Checker - https://Email-checker.net/validate

## Password OSINT (Hunting Breached Credentials)
* Dehashed - https://dehashed.com/
* WeLeakInfo - https://weleakinfo.to/v2/
* LeakCheck - https://leakcheck.io/
* SnusBase - https://snusbase.com/
* Scylla.sh - https://scylla.sh/ (goes down now and then)
* HaveIBeenPwned - https://haveibeenpwned.com/
* Breach-Parse - ( https://github.com/hmaverickadams/breach-parse)![afbeelding](https://github.com/DeadlyMouse113/hacker-toolbox/assets/121127124/e4074dc1-5412-4a8d-a231-360db30be8af)

## Username OSINT
* NameChk - https://namechk.com/
* WhatsMyName - https://whatsmyname.app/
* NameCheckup - https://namecheckup.com/

## People OSINT (people, phones, addresses, birthday...)
* WhitePages - https://www.whitepages.com/
* TruePeopleSearch - https://www.truepeoplesearch.com/
* FastPeopleSearch - https://www.fastpeoplesearch.com/
* FastBackgroundCheck - https://www.fastbackgroundcheck.com/
* WebMii - https://webmii.com/
* PeekYou - https://peekyou.com/
* 411 - https://www.411.com/
* Spokeo - https://www.spokeo.com/
* That'sThem - https://thatsthem.com/

## Domain names & Subdomains
* fierce (https://www.kali.org/tools/fierce/)
* https://www.nslookup.io/
* https://who.is
* https://crt.sh
* Sublist3r (https://www.kali.org/tools/sublist3r)
* OWASP Amass (https://owasp.org/www-project-amass) (https://github.com/owasp-amass/amass)
* dnsrecon (https://www.kali.org/tools/dnsrecon)
* dig (https://www.kali.org/tools/bind9/#dig)

## What technology is used?
* https://Builtwith.com
* Wappalyzer (firefox extension)
* WhatWeb (https://www.kali.org/tools/whatweb)
  
# ENUMERATION & SCANNING

## Network scanning
* netdiscover (https://www.kali.org/tools/netdiscover/)
* nmap (https://www.kali.org/tools/nmap/)

## Directory Busting
* Dirbuster (https://www-kali-org.translate.goog/tools/dirbuster/)
* Dirb (https://www.kali.org/tools/dirb/)
* Gobuster (https://www.kali.org/tools/gobuster/)
* ffuf (https://www.kali.org/tools/ffuf/)

## Active Directory
### Active Directory: Domain Enumeration (after account compromised)
* Bloodhound (https://www.kali.org/tools/bloodhound/)
* ldapdomaindump (https://www.kali.org/tools/python-ldapdomaindump/)
* Plumhound (https://github.com/PlumHound/PlumHound)
* PingCastle (https://www.pingcastle.com/)

# VULNERABILITY SCANNING
* Nessus (https://www.tenable.com/products/nessus)
* Nuclei (https://github.com/projectdiscovery/nuclei)

## Web Application analysis
* Nikto (https://www.kali.org/tools/nikto)
* Burpsuite (https://portswigger.net)

## Vulnerability Databases
* https://nvd.nist.gov/vuln/full-listing/
* https://www.exploit-db.com/
* https://www.cvedetails.com/
* Searchsploit (https://www.kali.org/tools/exploitdb/)

# EXPLOITATION
* Metasploit (https://www.kali.org/tools/metasploit-framework/)  	*This framework is used for a lot more...*

## Password Attacks
* Hydra (https://www.kali.org/tools/hydra/)
* Hashcat (https://www.kali.org/tools/hashcat/)
* John The ripper (https://www.kali.org/tools/john/)
* Medusa (https://www.kali.org/tools/medusa/)
* hash-identifier (https://www.kali.org/tools/hash-identifier/)
* https://crackstation.net/
* fcrackzip (https://www.kali.org/tools/fcrackzip/)
* https://hashes.com/en/tools/hash_identifier

## Privilege Escalation
* peas-ng (https://www.kali.org/tools/peass-ng/)
* https://gtfobins.github.io/

## Snooping
* pspy (https://github.com/DominicBreuker/pspy/blob/master/README.md)

## Active Directory
### Active Directory: Initial Attack Vectors
* Responder (https://www.kali.org/tools/responder/)
* impacket-ntlmrelayx (https://www.kali.org/tools/impacket-scripts/)
* mitm6 (https://github.com/dirkjanm/mitm6/) (https://pypi.org/project/mitm6/)
 
## Shell Access (alternatives msfconsole)
* impacket-wmiexec (https://www.kali.org/tools/impacket-scripts/)
* impacket-smbexec (https://www.kali.org/tools/impacket-scripts/)
* impacket-psexec (https://www.kali.org/tools/impacket-scripts/)

## Exploit Development
### Buffer OverFlows - Spiking
* Spike (https://www.kali.org/tools/spike/)

# POST COMPROMISE
## Active Directory
### Active Directory: Post-Compromise Attacks
* impakcet-secretsdump (https://www.kali.org/tools/impacket-scripts/)
* crackmapexec (https://www.kali.org/tools/crackmapexec/)

# OTHER HANDY TOOLS
## Proxy - VPN
* FoxyProxy (https://getfoxyproxy.org/, Browser Extension)

## SMB - SSH - Telnet
* smbclient (https://www.samba.org/samba/docs/current/man-html/smbclient.1.html)
* ssh (https://man7.org/linux/man-pages/man1/ssh.1.html)
* telnet (https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/telnet)

## Websites
* https://pentestmonkey.net/
* https://gtfobins.github.io/
* https://book.hacktricks.xyz

### Shells
* https://www.revshells.com/

### Encoder - Decoder
* https://www.urlencoder.org/
* 
### Obfuscation
* https://www.toptal.com/developers/javascript-minifier
* https://jsconsole.com/
* https://beautifytools.com/javascript-obfuscator.php

## Search tools
* strings (https://www.javatpoint.com/linux-strings-command)
* grep (https://www.cyberciti.biz/faq/howto-use-grep-command-in-linux-unix/)

# Repositories
* RunasCs (https://github.com/antonioCoco/RunasCs)
* nc (https://github.com/int0x33/nc.exe)
