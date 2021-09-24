# Network Forensic Analysis Report

## Overview
You are working as a Security Engineer for X-CORP, supporting the SOC infrastructure. The SOC analysts have noticed some discrepancies with alerting in the Kibana system and the manager has asked the Security Engineering team to investigate.

You will monitor live traffic on the wire to detect any abnormalities that aren't reflected in the alerting system. You are to report back all your findings to both the SOC manager and the Engineering Manager with appropriate analysis.

The Security team requested this analysis because they have evidence that people are misusing the network. Specifically, they've received tips about:

- "Time thieves" spotted watching YouTube during work hours.
- At least one Windows host infected with a virus.
- Illegal downloads.

A number of machines from foreign subnets are sending traffic to this network. Your task is to collect evidence confirming the Security team's intelligence.

## Time Thieves 
At least two users on the network have been wasting time on YouTube. Usually, IT wouldn't pay much mind to this behavior, but it seems these people have created their own web server on the corporate network. So far, Security knows the following about these time thieves:  
- They have set up an Active Directory network.  
- They are constantly watching videos on YouTube. 
- Their IP addresses are somewhere in the range `10.6.12.0/24`.  

Following Wireshark Filters were Used:

- Domain of the custom site: **`ip.addr == 10.6.12.0/24`**
- Traffic Inspection: **`ip.addr == 10.6.12.12`**
- Other Traffic Inspection: **`ip.addr == 10.6.12.203`**
- Malware Name: **`ip.addr == 10.6.12.203 and http.request.method == GET`**

You must inspect your traffic capture to answer the following questions:

1. What is the domain name of the users' custom site? 
   - **Domain Name:** `Frank-n-Ted-DC. frank-n-ted.com`
   - **Wireshark Filter:** `ip.src==10.6.12.0/24`
![Wireshark Filter](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_1-1a.PNG)  
2. What is the IP address of the Domain Controller (DC) of the AD network?
   - **IP Address:** `10.6.12.12 (Frank-n-Ted-DC.frank-n-ted.com)`
   - **Wireshark Filter:** `ip.src==10.6.12.0/24`
![IP Address](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_1-2a.png)  
3. What is the name of the malware downloaded to the `10.6.12.203` machine?
   - **Malware file name:** `june11.dll`
   - **Wireshark Filter:** `ip.addr == 10.6.12.0/24 and http.request.method == GET`
![Malware File Name](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_1-3.PNG)   
4. Upload the file to [VirusTotal.com](https://www.virustotal.com/gui/).
   - Exporting file to `Kali`:
     - Open File Tab
     - Export Objects
     - Select HTTP
     - Filter “*.dll”
     - Save june.dll
     - Upload to [VirusTotal.com](https://www.virustotal.com/gui/)
![Export](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_1-3a.PNG)  
![VirusTotal.com](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_1-a4.PNG)  
5. What kind of malware is this classified as?
   -  **The Trojan name is:** `Trojan.Mint.Zamg.O`
![The Trojan name is: Trojan.Mint.Zamg.O](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_1-4.PNG)  

## Vulnerable Windows Machine

The Security team received reports of an infected Windows host on the network. They know the following:

- Machines in the network live in the range `172.16.4.0/24`.
- The domain mind-hammer.net is associated with the infected computer.
- The DC for this network lives at `172.16.4.4` and is named Mind-Hammer-DC.
- The network has standard gateway and broadcast addresses.

Following Wireshark Filters were Used:

- Host Name, IP Address, MAC Address: `ip.addr == 172.16.4.0/24`
- Traffic Inspection: `ip.src == 172.16.4.4 && kerberos.CNameString`
- Username: `ip.src == 172.16.4.205 && kerberos.CNameString`
- Malicious Traffic: `ip.addr == 172.16.4.205 && ip.addr == 185.243.115.84`

Inspect your traffic to answer the following questions in your network report:

1. Find the following information about the infected Windows machine:
    - **Host name:** `ROTTERDAM-PC`
    - **IP address:** `172.16.4.205`
    - **MAC address:** `00:59:07:b0:63:a4`
    - **Wireshark Filter:** `ip.addr == 172.16.4.0/24`  
![IP Address](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_2-1.PNG)  
![MAC Address](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_2-1a.PNG)  
2. What is the username of the Windows user whose computer is infected?
   - **Username:** `matthijs.devries`
   - **Wireshark Filter:** `ip.src==172.16.4.205 && kerberos.CNameString`
![Username](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_2-2.PNG)  
3. What are the IP addresses used in the actual infection traffic?
   - **Filter:** `ip.src==172.16.4.203 and kerberos.CNameString`
   - I found `4` IP addresses: `172.16.4.205`, `185.243.115.84`, `166.62.11.64` and `23.43.62.169`
   - **Finding the IP addresses:**
     - Click on the Statistics Tab
     - Select the Conversation
     - Select the IPv4
     - Sort Packets high to low
![4 IP Address found](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_2-3-a.png)  
   - Additional Traffic from `185.243.115.84` to infected host `172.16.4.205`
![Additional Traffic](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_2-3a.PNG)  
4. As a bonus, retrieve the desktop background of the Windows host.
![Desktop Background](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_2-4.PNG)  
![Desktop Background](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/empty.gif_3fss_ss1img.png)  

---

## Illegal Downloads

IT was informed that some users are torrenting on the network. The Security team does not forbid the use of torrents for legitimate purposes, such as downloading operating systems. However, they have a strict policy against copyright infringement.

IT shared the following about the torrent activity:

- The machines using torrents live in the range `10.0.0.0/24` and are clients of an AD domain.
- The DC of this domain lives at `10.0.0.2` and is named DogOfTheYear-DC.
- The DC is associated with the domain dogoftheyear.net.

Following Wireshark Filters were Used:

- MAC Address: `ip.addr == 10.0.0.201 && dhcp`
- Username: `ip.src == 10.0.0.201 && kerberos.CNameString`
- Operating System: `ip.addr == 10.0.0.201 && http.request`
- Torrent Download: `ip.addr == 10.0.0.201 && http.request.method == "GET"`

Your task is to isolate torrent traffic and answer the following questions in your Network Report:

1. Find the following information about the machine with IP address `10.0.0.201`:
    - **MAC address:** `00:16:17:18:66:c8`
    - **Windows username:** `elmer.blanco`
    - **OS version:** `BLANCO-DESKTOP Windows NT 10.0`
    - **Wireshark Filter for MAC Address:** `ip.addr == 10.0.0.201 && dhcp`
![MAC Address](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_3-1a.PNG)  
    - **Wireshark Filter for Username:** `ip.addr == 10.0.0.201 && kerberos.CNameString`  
![Username](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_3-1b.PNG)  
    - **Wireshark Filter for OS Type and Version:** `ip.addr == 10.0.0.201 && http.request`  
![OS Type and Version](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_3-1b1.PNG)  
2. Which torrent file did the user download?
    - There were few that were downloaded, but below clip was show with the name:
    - Betty_Boop_Rhythm_on_the_Reservation.avi.torrent 
      - **Wireshark Filter:** `ip.addr == 10.0.0.201 && http.request.method == "GET"`
      - Finding the torrent:
      - Apply the Wireshark Filter above.
      - Sort the packets by the Destination files.publicdomaintorrents.com (`168.215.194.14`).
      - Look for Download requests.
![Publicdomaintorrents.com](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_3-1d.PNG)  
![Download](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/Part_3-1d1a.PNG)  
Movie Downloaded was Betty Boop Rhythm on the Reservation.avi  
![Movie](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%203/bettybooprythmonthereservationgrab.jpg)

---
  
## :sunglasses: `Ketan Vithal Patel` :sunglasses:  

### `Monday, September 13, 2021 -- UofT Cybersecurity - Boot Camp`
#### :rose::rose:`Jai Shri Swaminarayan`:rose::rose:
```
હરે કૃષ્ણ હરે કૃષ્ણ, કૃષ્ણ કૃષ્ણ હરે હરે |  Hare Krishna Hare Krishna, Krishna Krishna Hare Hare |
હરે રામ હરે રામ, રામ રામ હરે હરે ||   Hare Ram Hare Ram, Ram Ram Hare Hare ||
```
---  
