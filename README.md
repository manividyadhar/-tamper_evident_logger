# 🔐 Tamper-Evident Logging System

A secure logging system designed to ensure **log integrity and tamper detection** using **HMAC-based hash chaining**.

---

## 📖 Overview

Logs are critical for monitoring system activity, detecting threats, and performing forensic analysis. However, attackers often attempt to modify, delete, or reorder logs to hide their actions.

This project implements a **Tamper-Evident Logging System** that ensures any unauthorized change in logs is immediately detected.

The system uses **cryptographic techniques** to link log entries together, making it impossible to alter logs without breaking the chain.

---

## 🎯 Objectives

- Detect unauthorized modification of logs  
- Detect deletion of log entries  
- Detect reordering of logs  
- Maintain secure and consistent log storage  
- Provide clear verification output  
- Simulate real-world attack scenarios  

---

## 🧠 Core Concept

### 🔗 Hash Chaining

Each log entry is linked to the previous one:
# 🔐 Tamper-Evident Logging System

A secure logging system designed to ensure **log integrity and tamper detection** using **HMAC-based hash chaining**.

---

## 📖 Overview

Logs are critical for monitoring system activity, detecting threats, and performing forensic analysis. However, attackers often attempt to modify, delete, or reorder logs to hide their actions.

This project implements a **Tamper-Evident Logging System** that ensures any unauthorized change in logs is immediately detected.

The system uses **cryptographic techniques** to link log entries together, making it impossible to alter logs without breaking the chain.

---

## 🎯 Objectives

- Detect unauthorized modification of logs  
- Detect deletion of log entries  
- Detect reordering of logs  
- Maintain secure and consistent log storage  
- Provide clear verification output  
- Simulate real-world attack scenarios  

---

## 🧠 Core Concept

### 🔗 Hash Chaining

Each log entry is linked to the previous one:
- Detect unauthorized modification of logs  
- Detect deletion of log entries  
- Detect reordering of logs  
- Maintain secure and consistent log storage  
- Provide clear verification output  
- Simulate real-world attack scenarios  

---

## 🧠 Core Concept

### 🔗 Hash Chaining

Each log entry is linked to the previous one:


Log0 → Log1 → Log2 → Log3 → Log4

- Each entry stores the hash of the previous entry  
- Any change breaks the chain  
- The system detects inconsistencies immediately  

---

### 🔐 HMAC Security
HMAC = SHA256(secret_key + data)


- Uses a secret key for hashing  
- Prevents unauthorized hash recomputation  
- Ensures integrity and authenticity  

---

## 🏗️ System Architecture


User Input
↓
Input Validation
↓
Rate Limiter
↓
Log Creation Engine (HMAC)
↓
Secure Storage (JSON + Backup)
↓
Verification Engine
↓
Alert System
↓
Output / Report


---

## ⚙️ Features

- HMAC-based hash chaining  
- Detection of:
  - Log modification  
  - Log deletion  
  - Log reordering  
- Secure key management using environment variables  
- JSON-based structured logging  
- Backup and recovery mechanism  
- Tampering simulation module  
- Alert logging system  
- Export logs feature  

---

## 🔍 Security Mechanisms

- Cryptographic integrity protection (HMAC)  
- Chain-based validation (hash linking)  
- Environment-based secret key storage  
- Input validation and constraints  
- Rate limiting to prevent abuse  

---

## 📂 Log Structure

Each log entry contains:

json
{
  "index": 1,
  "timestamp": "2026-03-31T10:00:00Z",
  "event": "LOGIN",
  "description": "User logged in",
  "prev_hash": "abc123...",
  "current_hash": "def456..."
}
🧪 Tampering Detection

The system detects:

✅ Data modification → HMAC mismatch
✅ Log deletion → Chain break
✅ Log reordering → Hash mismatch
✅ Index tampering → Sequence inconsistency
▶️ How to Run
Step 1: Set Secret Key
export SECRET_KEY="your_secure_key"
Step 2: Run the Program
python3 tamper_log.py
🧪 Demo Workflow
Add log entries
Verify logs (INTACT)
Simulate tampering
Verify logs again (TAMPERED detected)
📁 Generated Files
logs.json → main log storage
logs.json.bak → backup file
alerts.log → tampering alerts
logs_export.txt → exported logs
🚨 Example Alert
[2026-03-31 14:32:14] ALERT | Entry 2 | HMAC mismatch detected
📊 Use Cases
Security monitoring systems
Audit logging
Financial transaction systems
Digital forensics
SOC (Security Operations Center) environments
🔐 Security Analysis
Strengths
Strong integrity protection
Immediate tamper detection
Real-world simulation
Secure key management
Limitations
No encryption of log data
Local system execution only
Depends on secure key management
🚀 Future Enhancements
AES encryption for log confidentiality
Cloud-based log storage
Integration with SIEM tools
Real-time monitoring dashboard
👨‍💻 Author

N. Mani Vidyadhar
Cybersecurity Enthusiast | SOC Aspirant

📌 Final Note

This system demonstrates a tamper-evident logging approach similar to blockchain-based integrity models, where each record is cryptographically linked to the previous one.

It provides a strong foundation for understanding secure logging in real-world cybersecurity systems.

