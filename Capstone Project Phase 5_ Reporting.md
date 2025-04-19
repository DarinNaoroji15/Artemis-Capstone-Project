# Capstone Project Phase 5 Reporting

Artemis Penetration Testing Report

April 11, 2025

By: Darin Naoroji

Table of Contents

Contents………………………………………………………………………………………………………………..1

1.0 Executive Summary………………………………………………………………………………………….2

1.1 Technical…………………………………………………………………………………………………………4

1.2 Scope of Work…………………………………………………………………………………………………..4

1.3 Project Objectives……………………………………………………………………………………………..4

1.4 Assumptions…………………………………………………………………………………………………….5

1.5 Timeline…………………………………………………………………………………………………………..5

1.6 Summary of Findings………………………………………………………………………………………..6

1.7 Recommendations……………………………………………………………………………………………9





1.0 Executive Summary
	
Artemis Gas, Inc., is a well established company with it being present in over 40 countries and over 30,000 employees. This company faces potential cybersecurity threats and challenges. This report will highlight key weaknesses within the company's IT infrastructure and evaluate the associated risks to business operations. To do this, one way is to evaluate and grade the vulnerabilities through a scoring system. CVSS or Common Vulnerability Scoring System has a standard that we follow to determine the 
severity of these threats. 

<img width="509" alt="image" src="https://github.com/user-attachments/assets/323d5613-22be-4cf1-8998-b14c7c993833" />

To keep data safe and systems running smoothly, Artemis Gas, Inc. needs to fix these security issues as soon as possible. The problems found are easy for attackers to discover and take advantage of with little effort. A key not to remember, this assessment might not catch every issue in the systems we looked at. Also, if any changes were made to the environment during testing, it could affect the results.

This report will assess the business impact through classifying using these classifications.

<img width="496" alt="image" src="https://github.com/user-attachments/assets/daa16970-5e83-4869-b2f3-4dc40e64d645" />












1.1 Technical Report
	
The APOLLO Security team performed an external penetration test on Artemis Gas Inc. The APOLLO Security team performed external box penetration testing on Artemis’ Web Application server. The aim of this assessment is to identify and expose vulnerabilities within Artemis Gas Inc. 's infrastructure. 
After ethical hacking of this infrastructure through penetration testing, we will provide and establish recommendations for remediation and resolution. During this engagement, the security team identified multiple high level vulnerabilities that utilized the internal network. This was found to be done through unrestricted access.

1.2 Scope of Work

This report will show the results obtained from vulnerability testing and assessing the threat through deep and thorough analysis. The scope of work shows network, web application client, and the IT Client Environment, covering critical infrastructure and applications.  

1.3 Project Objectives

The objective of the project is to find and identify the vulnerabilities and weaknesses in Artemis’s  internet infrastructure and web applications and servers. This will be shown through tables and analysis write ups from the results of the penetration tests. We will conduct the tests on items that can pose serious threats and vulnerability concerns through CVSS. These, if truly serious, are those that require immediate assessment and remediation. 

1.4 Assumptions

The assumptions that we make while crafting this report is that IP address are public information and that we should have granted full access to the Artemis’ network and systems. This way we can obtain an accurate and detailed assessment of the IT Client environment and the web applications.

1.5 Timeline

<img width="484" alt="image" src="https://github.com/user-attachments/assets/9ff9b729-e80d-43f8-8260-535a05040776" />


1.6 Summary of Findings

During the team’s assessment, we identified 9 scenarios that specifically require review. For these reviews, we will use this table from the Executive report to explain the severity of vulnerabilities that were found. 

<img width="409" alt="image" src="https://github.com/user-attachments/assets/48bebf6b-9a10-43ef-ba5b-2430e3c2a496" />


I am going to highlight the description of each vulnerability, which operating systems are affected, risks of attempting to exploit, risk (what could you or a threat actor do upon successful exploitation), the steps to take for remediation, and CVSS score them all.

Scenarios:

1.	Unpatched Remote Desktop Protocol (RDP) - Remote Desktop Protocol (RDP) is publicly exposed and remains unpatched, leaving it vulnerable to widely known exploits such as BlueKeep (CVE-2019-0708). These vulnerabilities allow attackers to execute commands remotely without any authentication. Once exploited, an attacker could gain full control over the system, leading to unauthorized access across the network. This creates an opportunity for lateral movement, data theft, or further exploitation of connected systems. The ease of discovery and exploitation makes this a high-priority concern, especially in production environments.

2.	SQL Injection in Web Application - The web application is susceptible to SQL injection due to improper handling of user input. This type of attack allows malicious actors to interfere with database queries, potentially bypassing authentication mechanisms. Once inside, attackers can view, alter, or delete sensitive data stored in the database. This vulnerability could also be used as a stepping stone to compromise additional systems. It represents a serious risk to data confidentiality and the integrity of application processes.

3.	Default Password on Cisco Admin Portal - Administrative interfaces on Cisco devices are still using default or factory-set credentials, which are widely known and easily exploited. An attacker who gains access can make configuration changes, disable protections, or intercept traffic. These credentials can be found in online documentation, making them a common first step for attackers. Full control over networking hardware can allow manipulation of internal communications and unauthorized access to other systems. This significantly compromises network integrity and overall security posture.

4.	Apache Server Vulnerability (CVE-2019-0211) - This vulnerability affects older versions of the Apache HTTP Server and enables local privilege escalation. A user with limited access can exploit the flaw to execute commands with root-level permissions. Once elevated, the attacker can modify server behavior, install malicious code, or tamper with hosted content. This poses a risk to both server integrity and the confidentiality of any data handled by the system. The flaw is particularly dangerous in shared hosting or multi-user environments.

5.	Exposed Sensitive Data via Web Server - The web server is unintentionally exposing sensitive files such as logs, backup archives, and configuration files. These files can provide attackers with valuable information about the server’s setup, user credentials, and internal application paths. Access to such data makes it easier for an attacker to plan targeted attacks or exploit other vulnerabilities. Even without active exploitation, data exposure can violate privacy policies and compliance standards. The presence of such files is often a sign of misconfiguration or lack of oversight.

6.	Broken Access Control in Web Application - The web application does not properly enforce user access restrictions, allowing unauthorized users to access sensitive features or data. This breakdown in access control violates principles like least privilege and zero trust. An attacker could exploit this to escalate their privileges, access restricted information, or impersonate other users. This not only compromises confidentiality but can also affect the integrity of the application. In some cases, APIs and endpoints are left unprotected, creating additional risks.

7.	Oracle WebLogic Remote Code Execution (CVE-2020-14882) - This critical vulnerability allows remote code execution through Oracle WebLogic’s administrative console. Attackers can exploit the flaw without authentication by sending specially crafted HTTP requests. Once compromised, the attacker can take full control of the server, execute commands, and potentially deploy malware or exfiltrate sensitive information. This vulnerability is particularly dangerous in internet-facing systems, where detection is more difficult. The level of access gained can lead to complete system compromise.

8.	Misconfigured Cloud Storage (AWS, etc.) - Improper configurations in cloud services—such as overly permissive AWS security groups or public S3 buckets—can expose sensitive data to unauthorized users. These misconfigurations are commonly exploited to access internal files, logs, and backups. Attackers can also identify active services or credentials stored in cloud environments, using them to pivot further into the infrastructure. Such exposures often go unnoticed until significant data has already been accessed. The risk spans both data confidentiality and service availability.

9.	Microsoft Exchange Vulnerability (CVE-2021-26855) - This Server-Side Request Forgery (SSRF) vulnerability in Microsoft Exchange allows attackers to send unauthorized HTTP requests through the server. It can be used to impersonate users, access email content, and execute remote commands. Attackers often follow this up by uploading web shells for persistent access and lateral movement. The vulnerability has been widely exploited in real-world attacks and is highly visible to advanced threat detection systems. Compromise of Exchange servers can lead to large-scale breaches of sensitive communications and internal data.

1.7 Recommendations

1.	Unpatched Remote Desktop Protocol (RDP) - Update all systems with the latest security patches, require VPN access for remote connections, and enforce Network Level Authentication (NLA) to reduce unauthorized access.

2.	Web Application – SQL Injection - Implement strict input validation and whitelisting, and enable logging and monitoring of all database activity to detect suspicious behavior.

3.	Default Password on Cisco Admin Portal - Replace default credentials with strong, unique passwords and disable insecure remote access methods like HTTP and Telnet.

4.	Apache Server: CVE-2019-0211 - Regularly audit user accounts and scripts on the server, and ensure Apache is upgraded to a secure, patched version. 

5.	Web Server Exposing Sensitive Data - Deploy Web Application Firewall (WAF) rules to block unauthorized access and remove sensitive files from public directories.

6.	Broken Access Control in Web Application - Ensure proper user authentication and authorization using the AAA framework, and log and report any unauthorized access attempts.

7.	Oracle WebLogic: CVE-2020-14882 - Apply the latest Oracle security patches and continuously monitor the system for any unexpected file changes or integrity issues.

8.	Misconfigured Cloud Storage - Tighten security group rules to limit access and apply strict permissions and encryption to cloud storage like S3 buckets.

9.	Microsoft Exchange: CVE-2021-26855 - Use Microsoft’s security tools to scan and mitigate the vulnerability, and implement advanced endpoint protection across all affected servers.
