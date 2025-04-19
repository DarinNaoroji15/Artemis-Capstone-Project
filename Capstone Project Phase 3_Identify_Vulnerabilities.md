# Capstone Project Phase 3 Identify Vulnerabilities

For this phase of the project I will be identifying the vulnerabilities for the target Artemis. This phase will require me to use and identify specific tools to find vulnerabilities within Artemis. These tools are useful for scanning and performing vulnerabilities. The tools in Kali Linux will include sufficient screenshots for how to exploit vulnerabilities. 

1.	Tenable Nessus

Tenable Nessus is a vulnerability scanner tool that is developed by Tenable that will help in investigating the Artemis organization. It assists in identifying vulnerabilities, misconfigurations, and compliance issues for a variety of devices. It can identify missing patches in various systems and applications.

How I will use Nessus: To set up Nessus, install Nessus and configure the tool to scan specifically the Artemis’ network. Create, define, and scan to the target IP ranges. The scan will bring back vulnerabilities, misconfigurations, and compliance issues. This tool will provide the results in the Nessus’ dashboard. This dashboard will prioritize the vulnerabilities on severity and the next step is to follow and remediate steps provided. 

Pros: 

●	User-friendly interface and gives detailed reports. 

●	The tool frequently updates and there is comprehensive scanning.

●	The tool is also versatile and offers cross-platform.

Cons:

●	The full version requires payment and full functionality.

●	It requires a lot of resources to do the scans. 
	 
![image](https://github.com/user-attachments/assets/52be9746-6b8e-43f9-8c85-249e76090290)
 
![image](https://github.com/user-attachments/assets/7b8d4fbe-71b0-4594-8737-70cb482baefe)

![image](https://github.com/user-attachments/assets/7042ed7e-6dbd-483d-b960-1c1a6b51a21d)


2.	Burp Suite

Burp Suite is a well known tool that is used for web application security. It offers a range of tools and focuses on exploiting web applications and weaknesses. These weaknesses can range from SQL injection, Cross Site scripting, etc. 

How I will use Burp Suite: To set up Burp Suite, I would install Burp Suite. I will configure Burp to intercept and take any web applications by Artemis. Then I will use the scanner to automate and will detect and report vulnerabilities. Then I will use the proxy tool to perform manual exploitation that I mentioned earlier for SQL injection or XSS.

Pros:

●	Offers both automated and manual testing methods.

●	It is comprehensive and an extremely powerful scanner.

Cons:

●	It can be quite hard for new users to learn and use.

●	The search is limited since it mainly focuses on web apps over other levels like network.
 

![image](https://github.com/user-attachments/assets/dbe1074e-c154-475a-ae6f-6d582d3159ea)

![image](https://github.com/user-attachments/assets/bf627c81-4fb6-46cc-9ce9-cbffaea9e6dc)

Encountered some problems with the application but I found an additional screenshot on how it should operate. 
 
![image](https://github.com/user-attachments/assets/58b301b7-e616-4da4-b055-b5b78d9eb4b8)

![image](https://github.com/user-attachments/assets/f4c570de-91fb-48d1-9cdb-1b5fb8241a90)

3.	Metasploit
	
Metasploit is a security framework and tool for penetration testing. This tool identifies, validates, exploits vulnerabilities in systems. Mainly used in testing the security posture and foundation networks and applications. 
	
How I will use Metasploit: I will install the software and scan the Artemis network. Then validate the vulnerability and then test for the exploits for the vulnerabilities. 
	
Pros:

●	This scanner is extremely customizable, allowing users to add and write modules, scripts, and exploits. 

●	The tool is open source and large community support adding on to the customizability. 

Cons:

●	The tool can be quite expensive for the pro version.

●	The tool can generate false positives and false negatives due to the automation. 

4.	OpenVAS

This tool is used for management and scanning. Can find and assess the security of computer systems and networks to find vulnerabilities, misconfigurations, and security weaknesses. This tool will assess and audit.

How will I use it: I will install and set up the app. I scan the network segments for Artemis. Then after scanning I will analyze the scan results through the detailed reports. 

Pros:

●	This app is free and open-source.

●	The app offers plenty of scanning options. 

Cons:

●	This app requires much more maintenance and setup than other tools.

●	The app is less intuitive and slows scans.

![image](https://github.com/user-attachments/assets/64a8fbf5-dce6-4971-8dce-782ee579583c)

5.	W3af

The application is an open source web application scanner. The tool helps identify and exploit web apps much like Burp Suite. Follow much of the same procedure that I did with Burp Suite. 

How I will use W3af: To set up W3af, I would install W3af. I will configure the app to intercept and take any web applications by Artemis. Then I will use the scanner to automate and will detect and report vulnerabilities. Then I will use the proxy tool to perform manual exploitation that I mentioned earlier for SQL injection or XSS.

Pros:

●	This tool supports GUI and CLI. 

●	It is super useful for learning and testing in a lab environment. 

Cons:

●	The app can be buggy.

●	The app can also be outdated with the plugins. 
