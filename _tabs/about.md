---
title: About
icon: fas fa-info
order: 4
---

I work as a cyber security researcher at one of the existing cyber security company in Turkey. Also, I'm trying to be a computer engineering student in my spare time. I'm a big fan of programming. My programming journey began with the my high school times. Since that time, I've written too many pointless programs, you can find some of them on my [github](https://github.com/fatihhcelik) page :)

Later, realized that I love cyber security and computer security related subjects mostly. Since that time, I've interested in web application security/programming and been trying to learn reverse engineering and low level stuff. Recently, I'm trying to involve into bug hunting and vulnerability researching world.

Also, I'm team lead at the [Hummingbirds Cyber Team](https://github.com/hummingbirdscyber/) which is the group of people working about computer security and artificial intelligence related subjects.

## Some of my projects

- **Detection of Windows Based Malwares Using Machine Learning**

In this project, we tried to understand the characteristics of the malwares and distinguish them from the benign files using machine learning techniques. Thanks to this project, we won the 3. place award in the one of the cyber security projects competition in Turkey.

- **Phishing Detection Using Machine Learning**

In this project, we tried to understand what is the idea and techniques behind of the phishing attacks and detect them. Thanks to this project, we won the 2. place award in the one of the cyber security projects competition in Turkey.

- **[OWASP Vulnerable Web Application Project](https://github.com/OWASP/Vulnerable-Web-Application)**

Vulnerable Web Application is a website that is prepared for people who are interested in web penetration and who want to have information about this subject.

- **[HackinOS Vulnerable Machine](https://www.vulnhub.com/entry/hackinos-1,295/)**

HackinOS is a beginner level CTF style vulnerable machine. I created this VM for my university’s cyber security community and all cyber security enthusiasts. I thank to Mehmet Oğuz Tozkoparan, Ömer Faruk Şenyayla and Tufan Güngör for their help during creating this lab.

## Security Advisories

- **CVE-2021-28855**

In Deark before 1.5.8, a specially crafted input file can cause a NULL pointer dereference in the dbuf_write function (src/deark-dbuf.c).

- **CVE-2021-28856**

In Deark before v1.5.8, a specially crafted input file can cause a division by zero in (src/fmtutil.c) because of the value of pixelsize.

- **CVE-2021-28060**

A Server-Side Request Forgery (SSRF) vulnerability in Group Office 6.4.196 allows a remote attacker to forge GET requests to arbitrary URLs via the url parameter to group/api/upload.php.

- **CVE-2020-35419**

Cross Site Scripting (XSS) in Group Office CRM 6.4.196 via the SET_LANGUAGE parameter.

- **CVE-2020-35418**

Cross Site Scripting (XSS) in the contact page of Group Office CRM 6.4.196 by uploading a crafted svg file.

- **CVE-2020-25538**

An authenticated attacker can inject malicious code into "lang" parameter in /uno/central.php file in CMSuno 1.6.2 and run this PHP code in the web page. In this way, attacker can takeover the control of the server.

- **CVE-2020-25557**

In CMSuno 1.6.2, an attacker can inject malicious PHP code as a "username" while changing his/her username & password. After that, when attacker logs in to the application, attacker's code will be run. As a result of this vulnerability, authenticated user can run command on the server.

- **CVE-2020-26803**

In Sentrifugo 3.2, users can upload an image under "Assets -> Add" tab. This "Upload Images" functionality is suffered from "Unrestricted File Upload" vulnerability so attacker can upload malicious files using this functionality and control the server.

- **CVE-2020-26804**

In Sentrifugo 3.2, users can share an announcement under "Organization -> Announcements" tab. Also, in this page, users can upload attachments with the shared announcements. This "Upload Attachment" functionality is suffered from "Unrestricted File Upload" vulnerability so attacker can upload malicious files using this functionality and control the server.

- **CVE-2020-26805**

In Sentrifugo 3.2, admin can edit employee's informations via this endpoint --> /sentrifugo/index.php/empadditionaldetails/edit/userid/2. In this POST request, "employeeNumId" parameter is affected by SQLi vulnerability. Attacker can inject SQL commands into query, read data from database or write data into the database.

- **CVE-2020-11827**

In GOG Galaxy 1.2.67, there is a service that is vulnerable to weak file/service permissions: GalaxyClientService.exe. An attacker can put malicious code in a Trojan horse GalaxyClientService.exe. After that, the attacker can re-start this service as an unprivileged user to escalate his/her privileges and run commands on the machine with SYSTEM rights.

- **CVE-2020-2909**

Vulnerability in the Oracle VM VirtualBox product of Oracle Virtualization (component: Core). Supported versions that are affected are Prior to 5.2.40, prior to 6.0.20 and prior to 6.1.6. Easily exploitable vulnerability allows low privileged attacker with logon to the infrastructure where Oracle VM VirtualBox executes to compromise Oracle VM VirtualBox. Successful attacks require human interaction from a person other than the attacker. Successful attacks of this vulnerability can result in unauthorized ability to cause a partial denial of service (partial DOS) of Oracle VM VirtualBox.

- **CVE-2020-11819**

In Rukovoditel 2.5.2, an attacker may inject an arbitrary .php file location instead of a language file and thus achieve command execution.

- **CVE-2020-11817**

In Rukovoditel V2.5.2, attackers can upload an arbitrary file to the server just changing the the content-type value. As a result of that, an attacker can execute a command on the server. This specific attack only occurs with the Maintenance Mode setting.

- **CVE-2020-11811**

In qdPM 9.1, an attacker can upload a malicious .php file to the server by exploiting the Add Profile Photo capability with a crafted content-type value. After that, the attacker can execute an arbitrary command on the server using this malicious file.

- **CVE-2020-11815**

In Rukovoditel 2.5.2, attackers can upload arbitrary file to the server by just changing the content-type value. As a result of that, an attacker can execute a command on the server. This specific attack only occurs without the Maintenance Mode setting.

- **CVE-2020-11816**

Rukovoditel 2.5.2 is affected by a SQL injection vulnerability because of improper handling of the reports_id (POST) parameter.

- **CVE-2020-11812**

Rukovoditel 2.5.2 is affected by a SQL injection vulnerability because of improper handling of the filters[0][value] or filters[1][value] parameter.

- **CVE-2020-11820**

Rukovoditel 2.5.2 is affected by a SQL injection vulnerability because of improper handling of the entities_id parameter.

- **CVE-2020-11826**

Users can lock their notes with a password in Memono version 3.8. Thus, users needs to know a password to read notes. However, these notes are stored in a database without encryption and an attacker can read the password-protected notes without having the password. Notes are stored in the ZENTITY table in the memono.sqlite database.

- **CVE-2020-11818**

In Rukovoditel 2.5.2 has a form_session_token value to prevent CSRF attacks. This protection mechanism can be bypassed with another user's valid token. Thus, an attacker can change the Admin password by using a CSRF attack and escalate his/her privileges.

- **CVE-2019-20074**

On Netis DL4323 devices, any user role can view sensitive information, such as a user password or the FTP password, via the form2saveConf.cgi page.

## Hall of Fame

- [U.S. Department of Defense](https://hackerone.com/r1gby?type=user)
- [AT&T](https://hackerone.com/r1gby?type=user)
- [Sony](https://hackerone.com/r1gby?type=user)
- [IBM](https://hackerone.com/r1gby?type=user)
- [Oracle](https://www.oracle.com/security-alerts/cpujul2020.html)
- [BMW Group](https://www.bmwgroup.com/en/general/Security.html)
- [Oracle](https://www.oracle.com/a/tech/docs/cpuapr2020cvrf.xml)
- [European Union](https://cert.europa.eu/cert/newsletter/en/latest_HallOfFame_.html)
- [Dell](https://bugcrowd.com/fatihhclk)
- [Telefonica Germany](https://bugcrowd.com/telefonicavdp)
- [Sophos](https://bugcrowd.com/sophos)
- University of Cambridge - Thanks letter
- [Drexel University](https://drexel.edu/it/security/services-processes/bug-bounty/)
