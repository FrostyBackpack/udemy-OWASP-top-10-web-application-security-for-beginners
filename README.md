# Objectives

Every self-respecting project manager, product owner and developer should follow this course.

- Understand the 10 most common web applications attacks, their impact and how these attacks can be prevented or mitigated

- Have access to technical documents that prevent or mitigate these attacks

## Introduction: OWASP Top 10 (Updated)

OWASP stands for Open Web Application Security Project.

|  #  |                     New                     |                        Old                        |
| :-: | :-----------------------------------------: | :-----------------------------------------------: |
|  1  |                  Injection                  |                     Injection                     |
|  2  |            Broken Authentication            | Broken Authentication ~~and Session Management ~~ |
|  3  |           Sensitive Data Exposure           |            Cross-Site Scripting (XSS)             |
|  4  |         ** XML External Entities **         |               Broken Access Control               |
|  5  |            Broken Access Control            |             Security Misconfiguration             |
|  6  |          Security Misconfiguration          |              Sensitive Data Exposure              |
|  7  |         Cross-Site Scripting (XSS)          |        ~~Insufficient Attack Protection ~~        |
|  8  |        **Insecure Deserialization **        |      ~~Cross Site Request Forgery (CSRF) ~~       |
|  9  | Using Components with Known Vulnerabilities |    Using Components with Known Vulnerabilities    |
| 10  |  **Insufficient logging and monitoring **   |                Underprotected APIs                |

### 2021 OWASP - Injection [# 1]

- What is it?
  <br/>
  Untrusted user input is interpreted <u>by server</u> and executed
  <br/>
  (It occurs when untrusted data is sent to a server as part of a command/query. So the attacker then sends malicious code in order to trick the server to execute/access data without proper authorization)

- What is the impact?
  <br/>
  Data can be stolen, modified or deleted

- How to prevent?
  <br/>

  - Reject untrusted/invalid input data
    <br/>
    (sanitizing input data - check whether the input data is valid)
  - Use latest framework
    <br/>
    (leverage their built-in capabilities to defend against injection)
  - Typically found by penetration testers/secure code review
    <br/>
    (hire penetration testers to penetrate your system from outside in, see whether they can leverage injection vulnerabilties or hire secure code review professionals to look at codes based from inside out and see whether your system is vulnerable to injection)

- Example:
  <br/>
  ![Injection](image/README/Injection.png)

### 2021 OWASP - Broken Authentication [# 2]

- What is it?
  <br/>
  Incorrectly build auth. and session man. scheme that allows an attacker to impersonate another user
  <br/>
  (It occurs when authentication and session management schemes are built or configured incorrectly such that an attacker can then impersonate a user)

- What is the impact?
  <br/>
  Attacker can take identity of victim
  <br/>
  (E.g. You do not want external people of your organization or colleagues with bad intentions to impersonate you because they could then execute several transactions without leaving traces that lead back to them. But these traces are then actually leading back to you)

- How to prevent?
  <br/>

  - Do not develop your own authentication schemes
    <br/>
    (it is very complex which allows you to make errors very quickly)
  - Use open source frameworks that are actively maintained by the community.
  - Use strong passwords (incl. upper, lower, number, special characters)
  - Require current credential when sensitive information is requested or changed
  - Multi-factor authentication (E.g. sms, password, fingerprint, iris scan etc.)
  - Log out or expire session after X amount of time
  - Be careful with 'remember me' functionality

- Example
  <br/>
  ![Broken Authentication](image/README/Broken%20Authentication.png)

### 2021 OWASP - Sensitive Data Exposure [# 3]

- What is it?
  <br/>
  Sensitive data is exposed
  <br/>
  (E.g. social security numbers, passwords, health records)

- What is the impact?
  <br/>
  Data that are lost, exposed or corrupted can have severe impact on business continuity

- How to prevent?
  <br/>

  - Always obscure data (credit card numbers are almost always obscured)
  - Update cryptographic algorithm (MD5, DES, SHA-0 and SHA-1 are insecure)
  - Use salted encryption on storage of passwords

- Example
  <br/>
  ![Sensitive Data Exposure](image/README/Sensitive%20Data%20Exposure.png)

### 2021 OWASP - XML External Entities [# 4]

- What is it?
  <br/>
  Many older or poorly configured XML processors evaluate external entity references within XML documents

- What is the impact?
  <br/>
  Extraction of data, remote code execution and denial of service attack

- How to prevent?
  <br/>

  - Use JSON, avoid avoiding serialization of sensitive data
  - Patch or upgrade all XML processors and libraries
  - Disable XXE and implement whitelisting
  - Detect, resolve and verify XXE with static application security testing tools

- Example
  <br/>
  ![XML External Entities](image/README/XML%20External%20Entities.png)

### 2021 OWASP - Broken Access Control [# 5]

- What is it?
  <br/>
  Restrictions on what authenticated users are allowed to do are not properly enforced
  <br/>
  (It occurs when authentication and session management schemes are built or configured incorrectly such that an attacker can then impersonate a user)

- What is the impact?
  <br/>
  Attackers can assess data, view sensitive files and modify data
  <br/>
  (An attacker can exploit these flaws by accessing unauthorized functionality to do all of the above)

- How to prevent?
  <br/>

  - Application should not solely rely on user input; check access rights on UI level and server level for requests to resources (E.g. data)
    <br/>
    (Authentication should be done on different levels and phases in the process so you can have one level - UI and a different phase could be for instance when the user tries to change data or try to modify data then you can ask the user to authorize to check user is authorized to modify data)
  - Deny access by default

- Example
  <br/>
  ![Broken Access Control](image/README/Broken%20Access%20Control.png)

### 2021 OWASP - Security Misconfiguration [# 6]

- What is it?
  <br/>
  Human mistake of misconfigurating the system
  <br/>
  (E.g. providing a user with a default password)

- What is the impact?
  <br/>
  Depends on the misconfiguration. Worst misconfiguration could result in loss of the system

- How to prevent?
  <br/>

  - Force change of default credentials
  - Least privilege: turn everything off by default (debugging, admin interface, etc.)
  - Static tools that scan code for default settings
  - Keep patching, updating and testing the system
  - Regularly audit system deployment in production

- Example
  <br/>
  ![Security Misconfiguration](image/README/Security%20Misconfiguration.png)

### 2021 OWASP - Cross-Site Scripting (XSS) [# 7]

- What is it?
  <br/>
  Untrusted user input is interpreted <u>by browser</u> and executed
  <br/>
  (It is similar to injection but it is through browser)

- What is the impact?
  <br/>
  Hijack user sessions, deface web sites, change content - redirect user to different malicious website
  <br/>
  (Allows attackers to execute scripts into victims browser to do all of the above)

- How to prevent?
  <br/>

  - Escape untrusted input data
  - Latest UI framework

- Example
  <br/>
  ![Cross-Site Scripting](image/README/Cross-Site%20Scripting.png)

### 2021 OWASP - Insecure Deserialization [# 8]

- What is it?
  <br/>
  Error in translations between objects

- What is the impact?
  <br/>
  Remote code execution, denial of service. Impact depends on type of data on that server

- How to prevent?
  <br/>

  - Validate user input
  - Implement digital signatures on serialized objects to enforce integrity
  - Restrict usage and monitor deserialization and log exceptions and failures

- Example
  <br/>
  ![Deserialization](image/README/Deserialization.png)
  <br/>
  ![Insecure Deserialization](image/README/Insecure%20Deserialization.png)

### 2021 OWASP - Using Components with Known Vulnerabilities [# 9]

- What is it?
  <br/>
  Third-party components that the local system uses (E.g. authentication frameworks)

- What is the impact?
  <br/>
  Depending on the vulnerability it could range from subtle to seriously bad

- How to prevent?
  <br/>

  - Always stay current with third-party components
  - If possible, follow the best practice of virtual patching

- Example
  <br/>
  ![Using Components with Known Vulnerabilities](image/README/Using%20Components%20with%20Known%20Vulnerabilities.png)

### 2021 OWASP - Insufficient logging and monitoring [# 10]

- What is it?
  <br/>
  Not able to witness or discover an attack when it happens or happened

- What is the impact?
  <br/>
  Allows attacker to persist and tamper, extract, or destroy your data without you noticing it

- How to prevent?
  <br/>

  - Log login, access control and server-side input validation failures
  - Ensure logs can be consumed easily, but cannot be tampered with
  - Continuously improve monitoring and alerting process
  - Mitigate impact of breach: Rotate, Repave and Repair
    - Rotate: changes keys/password frequently (multiple times a day)
    - Repave: restores the configuration to last good state (golden image)
    - Repair: patches vulnerability as soon as the patches are available

- Example
  <br/>
  ![Insufficient logging and monitoring](image/README/Insufficient%20logging%20and%20monitoring.png)

<hr/>

### 2021 OWASP - Cryptographic Failures

- What is it?
  <br/>
  Ineffective execution and configuration of cryptography
  <br/>
  (E.g. FTP, HTTP, MD5, WEP)

- What is the impact?
  <br/>
  Sensitive data exposure

- How to prevent?
  <br/>

  - Never roll your own crypto! Use well-known open source libraries
  - Static code analysis tools can discover this issue
  - Key management (creation, destruction, distribution, storage and use)

- Example
  <br/>
  ![Cryptographic Failures](image/README/Cryptographic%20Failures.png)

### 2021 OWASP - Insecure design

- What is it?
  <br/>
  A failure to use security by design methods/principles resulting in a weak or insecure design

- What is the impact?
  <br/>
  Breach of confidentiality, integrity and availability

- How to prevent?
  <br/>

  - Secure lifecycle (embed security in each phase; requirements, design, development, test, deployment, maintenance and decommissioning)\
  - Use manual (E.g. code review, threat modelling) and automated (E.g. SAST and DAST) methods to improve security

- Example
  <br/>
  ![Insecure Design](image/README/Insecure%20Design.png)

### 2021 OWASP - Software and Data Integrity Failures

- What is it?
  <br/>
  E.g. An application that relies on updates from a trusted external source, however the update mechanism is compromised

- What is the impact?
  <br/>
  Supply chain attack; data exfiltration, ransomware, etc.

- How to prevent?
  <br/>

  - Verify input (in this case software updates with digital signatures)
  - Continuously check for vulnerabilities in dependencies
  - Use Software Bill of materials
  - Unconnected back ups

- Example
  <br/>
  ![Software and Data Integrity Failures](image/README/Software%20and%20Data%20Integrity%20Failures.png)

### 2021 OWASP - Server-Side Request Forgery

- What is it?
  <br/>
  Misuse of prior established trust to access other resources. A web application is fetching a remote resource without validating the user-supplied URL

- What is the impact?
  <br/>
  Scan and connect to internal services. In some cases the attacker could access sensitive data

- How to prevent?
  <br/>

  - Sanitize and validate all client-supplied input data
  - Segment remote server access functionality in separate networks to reduce the impact
  - Limiting connections to specific ports only (E.g. 443 for https)

- Example
  <br/>
  ![Server-Side Request Forgery](image/README/Server-Side%20Request%20Forgery.png)

<hr/>

### 2017 OWASP - Insufficient Attack Protection [# 7]

- What is it?
  <br/>
  Applications that are attacked but do not recognize it as an attack, letting the attacker attack again and again

- What is the impact?
  <br/>
  Leak of data, decrease application availability

- How to prevent?
  <br/>

  - Detect and log normal and abnormal use of application (E.g. intrusion detection software)
  - Respond by automatically blocking abnormal users or range of IP addresses
  - Patch abnormal use quickly

- Example
  <br/>
  ![Insufficient Attack Protection](image/README/Insufficient%20Attack%20Protection.png)

### 2017 OWASP - Cross-Site Request Forgery (CSRF) [# 8]

- What is it?
  <br/>
  An attack that forces a victim to execute unwanted actions on a web application in which they are currently authenticated

- What is the impact?
  <br/>
  Victim unknowingly executes transactions

- How to prevent?
  <br/>

  - Reauthenticate for all critical actions (E.g. transfer money)
  - Include hidden token in request
  - Most web frameworks have built-in CSRF protection, but isn't enabled by default

- Example
  <br/>
  ![Cross-Site Request Forgery](image/README/Cross-Site%20Request%20Forgery.png)

### 2017 OWASP - Underprotected APIs [# 10]

- What is it?
  <br/>
  Applications expose rich connectivity options through APIs, in the browser to a user. These APIs are often unprotected and contain numerous vulnerabilities

- What is the impact?
  <br/>
  Data theft, corruption, unauthorized access, etc.

- How to prevent?
  <br/>

  - Ensure secure communication between client browser and server API
  - Reject untrusted/invalid input data
  - Use latest framework
  - Vulnerabilities are typically found by penetration testers and secure code reviewers

- Example
  <br/>
  ![Underprotected APIs](image/README/Underprotected%20APIs.png)

<hr/>

### BONUS

- Defense in depth
  <br/>
  ![Defense in depth](image/README/Defense%20in%20depth.png)
- STRIDE (basics)
  <br/>
  ![STRIDE-basics](image/README/STRIDE-basics.png)
- Secure development processes
  <br/>
  ![Secure development processes](image/README/Secure%20development%20processes.png)
- FAQ
  <br/>
  - How can you test whether your website uses the latest security protocols?
    <br/>
    Navigate to ssllabs.com to test the security protocols of your website for free.

  - Where can I (legally) test my hacking skills for free?
    <br/>
    There are several websites specifically for this need, for free (http://google-gruyere.appspot.com/)

  - What are Insecure Direct Object References?
    <br/>
    - What is it?
      <br/>
      A reference to a file, database or directory exposed to user via the browser

    - What is the impact?
      <br/>
      Any user can navigate to almost any part of the system and attack the system by modifying the URL through the browser

    - How to prevent?
      <br/>
      - Check access rights (E.g. proper authorization)
      - Input validation
    
    - Example
      <br/>
      ![Insecure Direct Object References](image/README/Insecure%20Direct%20Object%20References.png)