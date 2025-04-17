This next phase for the project requires the identification of network scans and targets. The tools I will assess for this part will come from Kali Linux. These tools are useful regarding host discovery, host enumeration, and any other enumeration techniques to be used. The following tools from Kali Linux will be discussed in this phase. 

1.	Nmap

Nmap is a tool useful for network exploration and security auditing. This tool will be incredibly helpful in finding all of the devices on Artemis’ network. It can also determine the different services running and figure out any underlying operating systems. There are elements of host discovery, port scanning, and OS detection that can be used for this tool. An example of a nmap command: nmap -A 192.168.1.1. This command will prompt a strong scan that includes OS detection and service version enumeration. Some of the challenges that can occur when using Nmap are issues with the network. When environments have extreme network configurations, like VPNs, NAT or other network configurations, Nmap is susceptible to missing particular hosts. The scans can be detected by the IDS and other security monitoring tools. 

2.	Whois

A command-line tool that can query databases regarding registration details of domains and IP addresses. The information can provide and indicate the ownership of domain, registration dates, and any contact details. The uses that are used for common uses to find who owns what, essentially its namesake. An example of this use case would be: whois artemis.com. This command queries all available DNS records for the domain artemis.com. Some challenges that can be encountered through privacy protection services that limit information that is available. Another challenge is that although this tool gives domain information and IP range ownership details, there is no technical information. 

3.	Netcat

This is a simple but powerful tool for network exploration, banner grabbing, transferring files, and opening ports for listening. It is so versatile as a tool it has been dubbed as the “Swiss army knife” of networking tools. An example of a command-line in Kali Linux: nc -zv 192.168.1.100 1-1024. This scans the first 1024 ports on the 192.168.100 for open ports. Some challenges that occur with Netcat is that the functionality is fairly limited in comparison to Nmap. Security gaps can occur if the system is misused or left open on a system. 

4.	Metasploit

This framework for testing vulnerabilities to exploit and test security weaknesses. It includes post exploitation tasks like helping ethical hackers to gain deeper access and understanding to a compromised system. Set Target IP through this example: set RHOST 192.168.1.5 and run the exploit by coding: exploit. Challenges that come with Metasploit is that IDS software and systems can detect. The program can be very complex for beginners and there are issues with legality of systems. 

5.	Wget / curl

Both wget and curl are great tools in web interaction and banner grabbing. It is used in requests to web servers, headers, files, and other pages through HTTP. As well as receiving server software and version information. An example of code command line prompt would be: wget http://artemis.com | wget http://artemis.com/file.zip | wget –server-response –spider http://artemis.com | wget -P /path/to/directory http://artemis.com/file.zip. These all provide ways to download a webpage, a file, retrieval of HTTP Headers, files to a specific directory. Curl similarly: curl -O http://artemis.com | curl http://artemis.com | curl -c artemiscentral.txt http://artemis.com. These commands download web pages, retrieve HTTP Headers, and save cookies to a file. All useful in retrieving webpage interactions, banner grabs, and downloading of files. Challenges of these tools are HTTP verification that can be detected and denied ability to write and CAPTCHA also can be an indicator that these tools are being used for different purposes. Also requires real human interaction.
