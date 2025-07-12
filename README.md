# Network Traffic Analyzer – Real-time VPC Flow Logs Analysis with AWS Athena

---

## 🚀 Project Overview

This project enables real-time analysis and anomaly detection of VPC Flow Logs using AWS Athena, helping cloud teams monitor and troubleshoot network traffic effectively. It automates the ingestion, querying, and visualization of VPC logs to detect unusual patterns like port scans, DDoS attacks, or unexpected traffic spikes.

---

## 📐 Architecture Diagram

[VPC Flow Logs] → [S3 Bucket (Log Storage)] → [AWS Athena] → [Query Results in S3]
↑
[AWS Lambda]
↓
[Anomaly Alerts / Dashboards]
---

## 🛠️ Tech Stack & Tools Used

- **AWS Services:** VPC Flow Logs, S3, Athena, Lambda, CloudWatch  
- **Infrastructure as Code:** Terraform  
- **Query Language:** SQL (Athena)  
- **Monitoring & Alerting:** CloudWatch, SNS (optional)  
- **Programming:** Python (for Lambda functions)  

---

## 📂 Repo Structure
```
network-traffic-analyzer/
│
├── README.md
├── athena-queries/
│   ├── create_vpc_flow_logs_table.sql
│   └── sample_anomaly_queries.sql
├── lambda/
│   └── lambda_function.py
└── infrastructure/
    └── main.tf
```  


## 📋 Setup Instructions

### 1. Configure VPC Flow Logs

- Enable VPC Flow Logs in your AWS VPC and direct logs to an S3 bucket.  
- Ensure the S3 bucket has proper permissions for Athena and Lambda to access logs.  

### 2. Deploy Infrastructure (Terraform)

- Navigate to the `infrastructure/` folder.  
- Initialize Terraform:  
  ```bash
  terraform init
## Apply Terraform scripts to create required S3 buckets for logs and Athena query results:
 terraform apply
### 3. Create Athena Table
Use the Athena query create_vpc_flow_logs_table.sql located in athena-queries/ to create an external table for VPC Flow Logs.

Run this in the Athena console, pointing the table location to your VPC logs S3 bucket.

### 4. Run Sample Anomaly Queries
Use sample_anomaly_queries.sql for detecting suspicious patterns such as high request rates, unusual ports, or repeated connection attempts.

Customize queries as needed for your environment.

### 5. Deploy Lambda Function (Optional)
The Lambda function in lambda/lambda_function.py can automate running Athena queries on schedule and trigger alerts.

Deploy this Lambda with an IAM role allowing Athena query execution and CloudWatch logging.

---

## 🗄️ Athena Table Creation Query

```sql
CREATE EXTERNAL TABLE IF NOT EXISTS vpc_flow_logs (
  version int,
  account_id string,
  interface_id string,
  srcaddr string,
  dstaddr string,
  srcport int,
  dstport int,
  protocol int,
  packets bigint,
  bytes bigint,
  start bigint,
  end bigint,
  action string,
  log_status string
)
PARTITIONED BY (dt string)
ROW FORMAT SERDE 'org.apache.hadoop.hive.serde2.RegexSerDe'
WITH SERDEPROPERTIES (
  'input.regex' = '^(\\d+)\\s+(\\d+)\\s+(\\S+)\\s+(\\S+)\\s+(\\S+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\S+)\\s+(\\S+)$'
)
LOCATION 's3://your-vpc-flow-logs-bucket/'
TBLPROPERTIES ('has_encrypted_data'='false');
```

### 🧰 What You’ll Learn

- How to set up VPC Flow Logs and analyze them using Athena

- Writing effective SQL queries for network anomaly detection

- Automating log analysis with AWS Lambda

- Using Terraform to manage AWS infrastructure declaratively

---
### 🙋‍♀️ Author
Kosha Gohil

Cloud Support Associate | AWS Solutions Architect – Associate | CompTIA Security+

 --- 
### 📫 Connect with Me
**LinkedIn:** https://www.linkedin.com/in/kosha-gohil

**Email:** gohilkosha@gmail.com

