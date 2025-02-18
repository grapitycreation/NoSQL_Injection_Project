# NoSQL-Injection-Project

**Acknowledgment:** This is my final project for the Web Security and Application course at my university with a team 4 members.

## 1. Introduction
### 1.1 NoSQL Overview
#### 1.1.1 What is NoSQL?
NoSQL, short for 'Not only SQL' or 'Non-SQL', is a type of database that does not use the relational table model like traditional Relational Database Management Systems (RDBMS). Instead, NoSQL stores and manages data in various models, such as key-value pairs (JSON, BSON), documents, columns, or graphs, enhancing scalability and performance for modern applications.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image001.png)

MongoDB is an open-source NoSQL database management system designed to store and manage data in a document format. Instead of using tables and rows like in relational databases (SQL), MongoDB uses collections and documents.

Some of the operators used in MongoDB include:

- **Comparison operators:** $eq, $gt, $lt,…
- **Logical operators:** $and, $or,…
- **Array operators:** $all, $elemMatch, $size.
- **Element operators:** $exists, $type.
- **Update operators:** $set, $unset, $inc.
- **Aggregation operators:** $group, $sort,…

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image002.png)

#### 1.1.2 Characteristics of NoSQL
The key characteristics of NoSQL include:

- **Schema-less structure:** NoSQL databases do not require a fixed schema, allowing for flexible and heterogeneous data storage.

- **Scalability:** NoSQL is typically designed for easy horizontal scaling, meaning additional servers can be added to handle large volumes of data.

- **High performance:** NoSQL is optimized for fast data queries, making it suitable for high-performance applications such as distributed systems and real-time applications.

- **Diverse data models:** NoSQL supports various data storage models, including Key-Value, Document, Column-Family, and Graph.

#### 1.1.3 Pros and Cons
**Pros:**
- **Flexible data structure:** The structure can be easily modified without the need to alter a fixed schema like in SQL.
- **High query speed:** Often provides faster queries when dealing with unstructured or semi-structured data.
- **Good scalability:** Suitable for large web applications and distributed systems.

**Cons:**

- **Weak support for strong consistency:** Many NoSQL databases follow the CAP Theorem, often prioritizing availability and partition tolerance over consistency.
- **Lack of standardization:** Unlike SQL, NoSQL databases do not have a universal standard, leading to different query and usage methods across systems.
- **Complex transaction handling:** NoSQL does not support complex transactions as effectively as relational database management systems (RDBMS).

  #### 1.1.4 When to use NoSQL
  NoSQL databases are suitable for the following scenarios:
  
- Storing unstructured or semi-structured data
- Requiring high scalability
- Needing high query performance
- Frequent changes in data and data structure
- Modern application models such as microservices and real-time streaming
- 
### 1.2 NoSQL Injection
#### 1.2.1 What is NoSQL Injection?
NoSQL Injection is a type of security attack in which an attacker injects malicious code into NoSQL queries to manipulate the operations of a NoSQL database.

The goal of this attack is to steal data, modify data without authorization, or disrupt the system.

NoSQL Injection is similar to SQL Injection but targets NoSQL databases (such as MongoDB, CouchDB, and Cassandra) instead of SQL-based databases.

According to OWASP Top 10 statistics, NoSQL Injection was among the top three most critical web security vulnerabilities from 2017 to 2021.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image003.png)

#### 1.2.2 How NoSQL Injection Works
If user input is not properly validated and sanitized, an attacker can inject modified queries to access unauthorized or unintended data.

NoSQL Injection queries vary depending on the type of NoSQL database being targeted.

For MongoDB, attackers can exploit injection in two ways:

- **Syntax Injection:** The attacker modifies the query syntax by adding or altering its structure, forcing the database to execute unintended queries that retrieve unauthorized data.

- **Operator Injection:** The attacker manipulates the query by injecting supported NoSQL operators, causing the database to execute queries that access restricted or unintended data.

#### 1.2.3 Consequences of a Successful NoSQL Injection

- **Unauthorized Access:** Attackers can bypass authentication and gain unauthorized access to data.

- **Data Leakage:** Sensitive application data may be exposed.

- **Data Manipulation:** Attackers can modify or delete critical data.

- **System Disruption:** Uncontrolled operations may cause system failures, impacting data integrity.

#### 1.2.4 Preventing NoSQL Injection
- **Input Validation and Sanitization:** Properly filter and sanitize user input to prevent special characters or operators from being injected.

- **Use Secure Libraries:** Utilize secure libraries or Object-Relational Mapping (ORM) tools that support safe queries to prevent malicious injections.

- **Restrict Access Permissions:** Grant the least privilege necessary to database accounts to minimize potential damage. MongoDB, for example, provides an IP Access List mechanism to allow only specific IP addresses to query the database.

- **Implement Strong Authentication and Encryption:** Ensure robust authentication mechanisms and use encryption to protect sensitive data.

### 1.3 Project Objectives

- Ensure that all team members understand how NoSQL databases work, as well as the causes, attack methods, and security mechanisms related to NoSQL Injection.

- Identify and demonstrate six attack scenarios on MongoDB, ranging from basic to advanced levels.

- Propose corresponding mitigation measures tailored to each attack scenario.

## 2. Scenario Deployment
### 2.1 Tool and softwares
- VS Code
- BurpSuite Community
- MongoDB Compass 1.45.0
- XAMPP 3.3.0
- PHP 8.3.13

### 2.2 Scenario 1: Authentication Bypass Attack (Custom Web Application)
#### 2.2.1 Vulnerability Description
On the login page, user inputs are not properly sanitized, allowing an attacker to inject malicious queries and log in without knowing the actual user’s password.

#### 2.2.2 Cause of the Vulnerability
The source code in the /Lib/Dao.php file uses a query function that does not sanitize user inputs, enabling attackers to inject malicious queries and bypass authentication.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image004.png)

Additionally, the application utilizes the json_decode function, which can introduce security risks if input validation is not strictly enforced. This makes it vulnerable to deserialization attacks, similar to traditional Deserialize Injection.

#### 2.2.3 Attack Steps
1. Navigate to the ```/login page``` of the web application.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image005.png)

2. Enter a known user’s email and use the following injection string as the password: ```{"$ne":"invalid"}```

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image006.png)

3. Successfully log in without needing the actual password.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image007.png)

#### 2.2.4 Impact Level

- Severity: High
  
- An attacker can log in using any account, including the admin account, compromising the security of all user data

#### 2.2.5 Mitigation Recommendations
- **Use Secure Frameworks:** Avoid writing custom frameworks as in this scenario to prevent insecure mechanisms or functions that lack input sanitization.

- **Sanitize and Validate User Input:** Always validate user input to prevent the use of special characters that could alter database queries.

- **Use Query Parameterization:** Implement parameterized queries to prevent attackers from injecting malicious queries into database operations.

- **Keep Software Updated:** Regularly update to the latest secure versions and apply security patches.

### 2.3 Scenario 2: Search Bar Attack (Custom Web Application)

#### 2.3.1 Vulnerability Description
The search bar on the ```/posts``` page does not sanitize user input, allowing an attacker to search for hidden posts without knowing their titles.

#### 2.3.2 Cause of the Vulnerability
The source code in ```/Lib/Dao.php``` contains a search query that does not properly sanitize user input. This allows attackers to inject search queries and retrieve all post information.

Since the application uses regular expressions (regex) for search queries and does not filter special characters, attackers can use regex-based injections to manipulate search results.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image008.png)

#### 2.3.3 Attack Steps
1. Log in and navigate to the ```/posts``` page.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image009.png)

2. Enter the search string:
```
.*
```
Since the web application uses regex for searching, the ```.*``` pattern will match all posts, including hidden ones.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image010.png)

3. The system displays all posts, including those that should remain hidden.

#### 2.3.4 Impact Level
- Severity: Medium
  
- Attackers can retrieve all post information, including hidden posts, which may lead to the exposure of upcoming content, potentially causing security and confidentiality issues.

#### 2.3.5 Mitigation Recommendations
- **Use Secure Frameworks:** Avoid custom-built frameworks as in this scenario to prevent insecure mechanisms and lack of input sanitization.

- **Sanitize and Validate User Input:** Ensure user input is sanitized to prevent special characters from altering query execution.

- **Use Query Parameterization:** Implement parameterized queries to prevent attackers from injecting malicious queries into search operations.

- **Keep Software Updated:** Regularly update to the latest secure versions and apply security patches.

### 2.4	Kịch bản 3 rootme NoSQL Injection - Blind: 
#### 2.4.1 Vulnerability Description
- The challenge checks for a flag but still allows the use of MongoDB operators such as ```$regex```.

- An attacker can exploit this to brute-force each character of the flag.

#### 2.4.2 Cause of the Vulnerability
-  The server does not block MongoDB operators, allowing users to brute-force each character of the flag.

#### 2.4.3 Attack Steps
1. Access the NoSQL Injection – Blind challenge on RootMe.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image011.png)

2. Modify the request parameter to:
```
flag[$regex]=^3
```
- If the server returns a valid response, the first character is ```3```.
- Repeat the process for subsequent characters using a Python script

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image012.png)

3. Run the following Python brute-force script:

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image013.png)

- The script iterates through uppercase letters, lowercase letters, numbers, and special characters.
- If the response contains "Yeah", the guessed character is correct.
- Continue until the full flag is retrieved.

**Final flag result:** 3@sY_n0_5q7_1nj3c710n

#### 2.4.4 Mitigation Recommendations
- **Use Secure Frameworks:** Avoid writing custom frameworks to prevent unsafe mechanisms and lack of input sanitization.

- **Sanitize and Validate User Input:** Always filter and validate user input to prevent query manipulation.

- **Use Query Parameterization:** Parameterize queries to prevent attackers from injecting malicious queries into MongoDB operations.

- **Keep Software Updated:** Regularly update to the latest secure versions and apply security patches.

### 2.5 Scenario 4: CVE 2021-22910 Rocketchat
#### 2.5.1 Vulnerability Description.
**CVE-2021-22910** is a security vulnerability in Rocket Chat application version 3.12.1, which allows attackers to exploit Blind NoSQL Injection on the server without needing to log in.

#### 2.5.2 Cause of the Vulnerability
The source code in ```/app/api/server/v1/users.js``` lacks mechanisms for sanitizing user queries, enabling attackers to retrieve password reset tokens and 2FA codes using the ```$where``` operator, provided they know the username.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image014.png)

Additionally, the ```sort```, ```fields```, and ```query``` values are processed through the ```parseJSONQuery()``` function without input validation, which compromises security if an injection occurs.

#### 2.5.3 Attack steps
1. Log in to an account as the APIs only allow user interaction.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image015.png)

2. Create a GET request with the body:
```
/api/v1/users.list?query={"$where":"this.username===admin+&&+(()=>{+throw+this.services.totp.secret+})()"}
```
The server will return the corresponding 2FA code.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image016.png)

![image])(https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image017.png)

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image018.png)

3. Log in with the newly reset password (executed via code).

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image019.png)

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image020.png)

#### 2.5.4 Impact Level
- Severity: High

- Attackers can easily obtain both password reset tokens and 2FA codes for all users, including admins, which poses a significant security risk to the entire system.

#### 2.5.5 Mitigation Recommendations
- **Use Secure Frameworks:** Avoid writing custom frameworks like in the scenario to prevent the use of insecure mechanisms or functions that lack input sanitization.

- **Sanitize and Validate User Input:** Always check user input to avoid the use of characters that could affect system queries.

- **Use Parameterization in Queries:** Parameterize functions related to queries to prevent attackers from injecting malicious query statements into the original query.

- **Regularly Update to the Latest Secure Version:** Frequently update security patches related to vulnerabilities.

### 2.6 Scenario 5: CVE-2024-28192 YourSpotify
#### 2.6.1 Vulnerability Description.
**CVE-2024-28192** is a security vulnerability in YourSpotify version 1.8.0 and earlier, which creates a NoSQL Injection vulnerability in the logic handling public access tokens. This allows attackers to bypass the public access token validation mechanism, regardless of whether the token was previously created.

#### 2.6.2 Cause of the Vulnerability
The source code in ```/server/src/tools/middleware.ts``` uses the ```getUserFromField``` function, which is insecure.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image021.png)

The ```getUserFromField``` function retrieves the value (i.e., user token) from the request without sanitizing it.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image022.png)

Additionally, ```Express.jsallows``` the creation of an object using the query ```?param[key]=value```.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image023.png)

This can lead to the injection string being changed to ```/me?token[$ne]=DOESNOTEXIST``` to retrieve the token. Alternatively, using the path ```/accounts``` retrieves the IDs of all users, resulting in CVE-2024-28193.

#### 2.6.3 Attack steps
1. Log in to an account.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image024.png)

2. Access the path ```/me?token[$ne]=DOESNOTEXIST``` at the API endpoint (localhost:8080) to retrieve the access token.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image025.png)

3. Access the path ```/accounts?token[$ne]=DOESNOTEXIST``` to retrieve the IDs of all users.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image026.png)

#### 2.6.4 Impact Level
- Severity: High

- Attackers can obtain the IDs of all users, leading to CVE-2024-28193, and subsequently steal user sessions through JWT tokens.

- From the session, attackers can change users' passwords and steal accounts.

#### 2.6.5 Mitigation Recommendations
- **Use Secure Frameworks:** Avoid writing custom frameworks as in this scenario to prevent the use of insecure mechanisms or functions that lack input sanitization.

- **Sanitize and Validate User Input:** Always check user input to avoid the use of characters that could affect system queries.

- **Use Parameterization in Queries:** Parameterize functions related to queries to prevent attackers from injecting malicious query statements into the original query.

- **Regularly Update to the Latest Secure Version:** Frequently update security patches related to vulnerabilities.

### 2.7 Scenario 6: CVE-2021-22911 Rocketchat
#### 2.7.1 Vulnerability Description.
**CVE-2021-22911** is a security vulnerability in Rocket Chat application version 3.12.1, which allows attackers to exploit Blind NoSQL Injection and brute force each character of the password on the server without needing to log in.

#### 2.7.2 Cause of the Vulnerability
The source code in ```/server/methods/getPasswordPolicy.js``` does not use sanitization mechanisms, allowing attackers to use ```{"$regex":"^A"}``` to brute force each character of the reset password token.

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image027.png)

#### 2.7.3 Attack step
1. Create a Python attack file as follows

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image028.png)

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image029.png)

2. Observe the results after running the code

![image](https://github.com/grapitycreation/NoSQL_Injection_Project/blob/main/images/image030.png)

#### 2.7.4 Impact Level
- Severity: High

- Attackers can obtain the reset password token of a specific user, especially if there are fewer users. As the attack sequence compares with the tokens, the fewer the users, the more certain it is that the token belongs to a particular user.

#### 2.7.5 Mitigation Recommendations
- **Use Secure Frameworks:** Avoid writing custom frameworks as in this scenario to prevent the use of insecure mechanisms or functions that lack input sanitization.

- **Sanitize and Validate User Input:** Always check user input to avoid the use of characters that could affect system queries.

- **Use Parameterization in Queries:** Parameterize functions related to queries to prevent attackers from injecting malicious query statements into the original query.

- **Regularly Update to the Latest Secure Version:** Frequently update security patches related to vulnerabilities.

## 3. Conclusion
Through the process of carrying out the project, group members have gained fundamental knowledge about NoSQL databases and NoSQL Injection attacks. Consequently, they have identified that vulnerabilities still exist in projects, primarily due to improper handling of input and the use of outdated versions of open-source projects.

## 4. Referrences
- https://portswigger.net/web-security/nosql-injection
- https://cve.mitre.org/cve/search_cve_list.html
- https://hackerone.com/
- https://www.root-me.org/
- https://www.geeksforgeeks.org/introduction-to-nosql/
















