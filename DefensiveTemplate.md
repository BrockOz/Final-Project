# Blue Team: Summary of Operations

## Table of Contents
- Network Topology
- Description of Targets
- Monitoring the Targets
- Patterns of Traffic & Behavior
- Suggestions for Going Further

### Network Topology
![Network Topology](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Network%20Topology-Diagram.PNG)  
The following machines were identified on the network:
- Name of VM 1 **`Hyper V Host Manager`**  
  - **Operating System:** `Windows 10`  
  - **Purpose:** `Contains the vulnerable machines and the attacking machine`  
  - **IP Address:** `192.168.1.1`  
- Name of VM 2 **`Kali`**  
  - **Operating System:** `Linux 5.4.0`  
  - **Purpose:** `Used as attacking machine`  
  - **IP Address:** `192.168.1.90`  
- Name of VM 3 **`Capstone`**  
  - **Operating System:** `Linux (Ubuntu 18.04.1 LTS)`  
  - **Purpose:** `Used as a testing system for alerts`  
  - **IP Address:** `192.168.1.100`  
- Name of VM 4 **`ELK`**  
  - **Operating System:** `Linux (Ubuntu 18.04.1 LTS)`  
  - **Purpose:** `Used for gathering information from the victim machine using Metricbeat, Filebeats, and Packetbeats`  
  - **IP Address:** `192.168.1.100`  
- Name of VM 5 **`Target 1`**  
  - **Operating System:** `Linux 3.2 - 4.9`  
  - **Purpose:** `The VM with WordPress as a vulnerable server`  
  - **IP Address:** `192.168.1.110`  
- Name of VM 6 **`Target 2`**  
  - **Operating System:** `Linux 3.2 - 4.9`  
  - **Purpose:** `The VM with WordPress as a vulnerable server`  
  - **IP Address:** `192.168.1.115`  

### Description of Targets

The target of this attack was: **`Target 1`** (192.168.1.110) and **`Target 2`** (192.168.1.115).

Both Targets expose the same WordPress site, however **`Target 2`** has better security hardening.

**`Target 1`** and **`Target 2`** are _Apache web server_ and has `SSH` enabled, so ports `80` and `22` are possible ports of entry for attackers. As such, the following alerts have been implemented:

### Monitoring the Targets

Traffic to these services should be carefully monitored. To this end, we have implemented the alerts below:

#### Excessive HTTP Errors

Excessive HTTP Errors is implemented as follows:
  - **Metric**: `Packetbeat:` http.response.status_code > 400
  - **Threshold**: `grouped http response status codes above 400 every 5 minutes`  
    - **`When count() GROUPED OVER top5 ‘http.response.status_code’ is above 400 for the last 5 minutes`**
  - **Vulnerability Mitigated**:  
    - Used intrusion detection/prevention for attacks  
    - IPS would block any suspicious IP’s  
    - Utilize Account Management to lock or request user accounts to change the passwords every 60 days  
    - Filter and disable or close port 22  
  - **Reliability**: This alert will not generate an excessive amount of false positives identifying brute force attacks. **`Medium`**
![Excessive HTTP Errors](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Excessive_HTTP_Errors_Create-1A.png)  
#### CPU Usage Monitor
CPU Usage Monitor is implemented as follows:
  - **Metric**: `Metricbeat:` system.process.cpu.total.pct
  - **Threshold**: The maximum cpu total percentage is over .5 in 5 minutes  
    - **`WHEN max() OF system.process.cpu.total.pct OVER all documents IS ABOVE 0.5 FOR THE LAST 5 minutes`**  
  - **Vulnerability Mitigated**: Controlling the CPU usage percentage at 50%, it will trigger a memory alert only if the CPU remains at or above 50% consistently for 5 minutes. Virus or Malware
  - **Reliability**: Yes, this alert can generate a lot of false positives due to CPU spikes occurring when specific integrations are initiated at the start of processing. **`High`**  
![CPU Usage Monitor](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/CPU_Usage_Monitor_Create.PNG)  
#### HTTP Request Size Monitor
HTTP Request Size Monitor is implemented as follows:
  - **Metric**: `Packetbeat:` http.request.bytes
  - **Threshold**: The sum of the requested bytes is over 3500 in 1 minute
    - **`When sum() of http.request.bytes OVER all documents is ABOVE 3500 for the LAST 1 minute`**
  - **Vulnerability Mitigated**: By controlling the number of http request sizes through a filter, protection is enabled to detect or prevent DDOS attacks for IPS/IDS.
  - **Reliability**: No, this alert doesn't generate an excessive amount of false positives because DDOS attacks submit requests within seconds, not within minutes. **`Medium`**
![HTTP Request Size Monitor](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/HTTP_Request_Size_Monitor_Create.PNG)  


---
  
## :sunglasses: `Ketan Vithal Patel` :sunglasses:  

### `Monday, September 13, 2021 -- UofT Cybersecurity - Boot Camp`
#### :rose::rose:`Jai Shri Swaminarayan`:rose::rose:
```
હરે કૃષ્ણ હરે કૃષ્ણ, કૃષ્ણ કૃષ્ણ હરે હરે |  Hare Krishna Hare Krishna, Krishna Krishna Hare Hare |
હરે રામ હરે રામ, રામ રામ હરે હરે ||   Hare Ram Hare Ram, Ram Ram Hare Hare ||
```
---  
