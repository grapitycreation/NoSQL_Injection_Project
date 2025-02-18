# NoSQL-Injection-Project

**Acknowledgment:** This is my final project for the Web Security and Application course at my university.

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

### 1.3




















