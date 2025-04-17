This phase of the project will require me to fully assess and understand the following scenarios below. I am going to highlight the description of each vulnerability, which operating systems are affected, risks of attempting to exploit, risk (what could you or a threat actor do upon successful exploitation), the steps to take for remediation, and CVSS score them all.

1.	Unpatched RDP is exposed to the internet

●	Description of the vulnerability

RDP or Remote Desktop Protocol allows users to connect to other computers over a network connection. If this is left unpatched it becomes a serious entry point for attackers to onto the network. BlueKeep (CVE-2019-0708) is a kind of vulnerability that allows unwarranted and unauthenticated code execution. As well as brute force attacks to gain access. 

●	Operating systems/versions affected

Most of the Windows Operating systems, especially older, and Windows servers 2003 - 2019.

●	Risks of attempting to exploit (e.g. might crash the host or lock out an account)

-	System crashes can occur.

-	The IDS or Intrusion Detection Systems can detect these exploitation attempts.

-	Account lockouts and legal risks can arise (if ethical).

●	Risk (what could you or a threat actor do upon successful exploitation)?

○	Identify as many attack vectors as you can. Examples: launch an attack on internal systems, obtain password hashes, crack passwords, access other systems, move laterally, and so on).

-	Gaining remote desktop access.

-	Harvesting password hashes.

-	Exfiltration of data.

○	Identify potential blocking mechanisms such as AV software or IDS/IPS, and how you might try to bypass them.

-	EDR: To bypass, obfuscate payloads and pack binaries.

-	MFA: To bypass, use social engineering techniques and brute force with more attempts and password reuse.

-	Account lockout: Password spray instead of brute forcing and delay the password attempts.

○	Document how you plan on cracking passwords. This will depend of course on the source system, but you should be ready for whatever you run into. Include online tools as well.

-	Capture credentials through keylogger or memory, using Powershell, etc.

-	RDP tools like crowbar and rdpscan for online tool.

●	Remediation action

-	Patch the systems.

-	Use VPN for remote access.

-	Enable NLA or Network Level Authentication. 

●	CVSS score

9.8 Critical score.


2.	Web application is vulnerable to SQL Injection

●	Description of the vulnerability

SQL injection essentially happens when user input is unvalidated and unsafely put into SQL queries. 

●	Operating systems/versions affected

MySQL, PostgreSQL, Oracle, Microsoft SQL Server.

●	Risks of attempting to exploit (e.g. might crash the host or lock out an account)

-	IDS/IPS services can detect payloads that are common.

-	Tampering with sensitive data can raise suspicions.

-	Crashes with the database could occur.

●	Risk (what could you or a threat actor do upon successful exploitation)?

○	Identify as many attack vectors as you can. Examples: launch an attack on internal systems, obtain password hashes, crack passwords, access other systems, move laterally, and so on).

-	Bypassing authentication.

-	Moving laterally and harvesting credentials.

-	Exploiting, deleting, editing, or reading sensitive data from databases.

○	Identify potential blocking mechanisms such as AV software or IDS/IPS, and how you might try to bypass them.

-	Web Application Firewall: To bypass this, use obfuscated payloads.

-	CAPTCHA: To bypass this, using headless browsers and proxies.

-	IDS/IPS: To bypass this, tamper the scripts.

○	Document how you plan on cracking passwords. This will depend of course on the source system, but you should be ready for whatever you run into. Include online tools as well.

-	Extract the password hashes, salts, logins, etc.

-	Use rainbow tables.

-	hashes.com is an online tool you can use.

●	Remediation action

-	 Enable logging and monitoring DB queries.

-	 Input validation and whitelist.

●	CVSS score

9.8 Critical score.



3.	Default password on Cisco admin portal

●	Description of the vulnerability

Using default password can allow attackers to gain full admin control over the network device. 

●	Operating systems/versions affected

Cisco ASA, Meraki, Cisco IOS.

●	Risks of attempting to exploit (e.g. might crash the host or lock out an account)

-	Brute force lockout from too many login attempts

-	Logging and alerts can show up

●	Risk (what could you or a threat actor do upon successful exploitation)?

○	Identify as many attack vectors as you can. Examples: launch an attack on internal systems, obtain password hashes, crack passwords, access other systems, move laterally, and so on).

-	Weaken security settings

-	On-path attacks or Man-in-middle to intercept communication.

○	Identify potential blocking mechanisms such as AV software or IDS/IPS, and how you might try to bypass them.

-	IP restrictions: To bypass this, using VPNs.

-	ACLs/Firewall: To bypass this, find open communication ports. 

○	Document how you plan on cracking passwords. This will depend of course on the source system, but you should be ready for whatever you run into. Include online tools as well.

-	Use tools like cisco7crack

-	Use online tool like crackstation.net

●	Remediation action

-	Enforce stronger password policies.

-	Disable remote access like HTTP or Telnet.

●	CVSS score

10.0 critical score.



4.	Apache web server vulnerable to CVE-2019-0211

●	Description of the vulnerability

CVE-2019-0211 is a local privilege escalation vulnerability in the Apache HTTP Server. To allow unauthorized higher level control.

●	Operating systems/versions affected

Apache HTTP servers 2.4.17 to 2.4.38 on Unix OS.

●	Risks of attempting to exploit (e.g. might crash the host or lock out an account)

-	Detection can occur either through logs or IDS or IPS. 

-	Segmentation faults or core dumps can occur.

●	Risk (what could you or a threat actor do upon successful exploitation)?

○	Identify as many attack vectors as you can. Examples: launch an attack on internal systems, obtain password hashes, crack passwords, access other systems, move laterally, and so on).

-	Could cause complete control over the server. 

-	Modifying modules and binaries.

-	Exploit memory corruption.

○	Identify potential blocking mechanisms such as AV software or IDS/IPS, and how you might try to bypass them.

-	IDS/IPS: To bypass, add time-based attacks.

-	Apache hardening: To bypass, check if a vulnerable and outdated version is still running, then exploit that.

○	Document how you plan on cracking passwords. This will depend of course on the source system, but you should be ready for whatever you run into. Include online tools as well.

-	Extracting password hashes.

-	Hydra.

●	Remediation action

-	Audit all local users and running scripts.

-	Upgrade the server and install patches if possible.

●	CVSS score

8.8 High score.



5.	Web server is exposing sensitive data

●	Description of the vulnerability

Allowing unauthorized users to access and exfiltrate sensitive data through the use of web servers.

●	Operating systems/versions affected

Linux servers, Windows, Apache, etc.

●	Risks of attempting to exploit (e.g. might crash the host or lock out an account)

-	Can potentially be visible to cyber defenders.

-	Can potentially trigger the web application firewall.

●	Risk (what could you or a threat actor do upon successful exploitation)?

○	Identify as many attack vectors as you can. Examples: launch an attack on internal systems, obtain password hashes, crack passwords, access other systems, move laterally, and so on).

-	File backups on server.

-	Exposed logs.

-	Access to environment files.

○	Identify potential blocking mechanisms such as AV software or IDS/IPS, and how you might try to bypass them.

-	File permissions set properly: To bypass, look for backups or leaked logs/debugs.

-	No directory listing: To bypass, try to common file names conventions and directory names.

○	Document how you plan on cracking passwords. This will depend of course on the source system, but you should be ready for whatever you run into. Include online tools as well.

-	Extracting password and hashes.

-	Identify hash formats like SHA1 and MD5.

●	Remediation action

-	Using WAF rules to block unauthorized actions against the web server.

-	Removing sensitive files from web root.

●	CVSS score

7.5 High score.



6.	Web application has broken access control

●	Description of the vulnerability

Failure in enforcing the restrictions on web application and access controls. Which breaks the zero trust and least privilege. 

●	Operating systems/versions affected

Windows servers and Linux. 

●	Risks of attempting to exploit (e.g. might crash the host or lock out an account)

-	Account lockouts.

-	Can log potential impersonation attempts. 

●	Risk (what could you or a threat actor do upon successful exploitation)?

○	identify as many attack vectors as you can. Examples: launch an attack on internal systems, obtain password hashes, crack passwords, access other systems, move laterally, and so on).

-	Privilege escalation.

-	Unprotected APIs.

○	Identify potential blocking mechanisms such as AV software or IDS/IPS, and how you might try to bypass them.

-	JavaScript-based restrictions: To bypass, use burp suite.

-	Role-based checks: To bypass, replay tokens and test any expired or outdated tokens. 

○	Document how you plan on cracking passwords. This will depend of course on the source system, but you should be ready for whatever you run into. Include online tools as well.

-	Find database dumps or log files.

-	Misconfigured endpoints/users/accounts. 

●	Remediation action

-	Ensure each user is validated through the AAA framework. 

-	Log any unauthorized attempts and report. 

●	CVSS score

9.8 Critical score.



7.	Oracle WebLogic Server vulnerable to CVE-2020-14882

●	Description of the vulnerability

CVE-2020-14882 is a Remote Code Execution (RCE) vulnerability in Oracle WebLogic Server. This is the execution of arbitrary code on the server that sends a HTTP request to the admin console. 

●	Operating systems/versions affected

Oracle WebLogic Servers: 10.3.6.0.0, 12.1.3.0.0, 12.2.1.3.0, 12.2.1.4.0, 14.1.1.0.0

●	Risks of attempting to exploit (e.g. might crash the host or lock out an account)

-	Crashes can occur if payload is misconfigured.

-	Post-exploitation commands can be blocked or logged.

●	Risk (what could you or a threat actor do upon successful exploitation)?

○	Identify as many attack vectors as you can. Examples: launch an attack on internal systems, obtain password hashes, crack passwords, access other systems, move laterally, and so on).

-	Installing malware and ransomware.

-	Harvesting credentials.

○	Identify potential blocking mechanisms such as AV software or IDS/IPS, and how you might try to bypass them.

-	Patch management: How to bypass, if the system is unpatched or in the process of being patched, then exploit.

-	IP whitelist/firewall: How to bypass, exploit from allowed IP through proxy and pivoting.

○	Document how you plan on cracking passwords. This will depend of course on the source system, but you should be ready for whatever you run into. Include online tools as well.

-	Using John the Ripper can work.

-	Using Mimikatz to extract Windows credentials.

●	Remediation action

-	Apply Oracle Patches.

-	Monitor file integrities. 

●	CVSS score

9.8 Critical score.



8.	Misconfigured cloud storage (AWS security group misconfiguration, lack of access restrictions)

●	Description of the vulnerability

This occurs when improper and incorrect configurations in cloud infrastructure.

●	Operating systems/versions affected

AWS, Azure, Linux, etc.

●	Risks of attempting to exploit (e.g. might crash the host or lock out an account)

-	Possible logging in IP through the cloud provider using CloudTrial or Flow Logs. 

-	Can disrupt critical systems by deleting and modifying files.

●	Risk (what could you or a threat actor do upon successful exploitation)?

○	Identify as many attack vectors as you can. Examples: launch an attack on internal systems, obtain password hashes, crack passwords, access other systems, move laterally, and so on).

-	Query any exposed buckets.

-	Exploiting accessible services.

○	Identify potential blocking mechanisms such as AV software or IDS/IPS, and how you might try to bypass them.

-	AWS GuardDuty/Config: How to bypass, avoid known malicious IPs.

-	MFA on IAM accounts: How to bypass, avoid login attempts. 

○	Document how you plan on cracking passwords. This will depend of course on the source system, but you should be ready for whatever you run into. Include online tools as well.

-	AWS sts assume-role. 

-	Hashcat tool.

●	Remediation action

-	Restricting security Group access.

-	Harden the S3 buckets.

●	CVSS score

9.0 Critical score.



9.	Microsoft Exchange Server vulnerable to CVE-2021-26855

●	Description of the vulnerability

CVE-2021-26855 is a Server-Side Request Forgery (SSRF) vulnerability in Microsoft Exchange Server. When arbitrary HTTP requests are sent and authenticated through the exchange server itself.

●	Operating systems/versions affected

Exchange Server 2013, 2016, 2019.

●	Risks of attempting to exploit (e.g. might crash the host or lock out an account)

-	Exploiting activity is extremely visible in the logs for detection systems like EDR/XDR systems.

-	Defender can detect the web shell payloads.

●	Risk (what could you or a threat actor do upon successful exploitation)?

○	Identify as many attack vectors as you can. Examples: launch an attack on internal systems, obtain password hashes, crack passwords, access other systems, move laterally, and so on).

-	Mailbox access and web shell upload through /owa/auth path.

-	Execution of DLLs or scripts.

○	Identify potential blocking mechanisms such as AV software or IDS/IPS, and how you might try to bypass them.

-	Endpoint protection: How to bypass, obfuscate the payloads.

-	SSL Inspection: HTTPS over custom C2.

○	Document how you plan on cracking passwords. This will depend of course on the source system, but you should be ready for whatever you run into. Include online tools as well.

-	Kerberoasting to the Active Directory.

-	Windows Credential Manager Dump.

●	Remediation action

-	Run Microsoft’s safety scanner and exchange on-premises mitigation tool.

-	Deploy endpoint hardening and EDR implemented across all the exchange-connected servers.

●	CVSS score

9.8 Critical score.
