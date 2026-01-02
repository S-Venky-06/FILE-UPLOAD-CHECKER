# 🔐 Malicious File Upload Detection Engine

A **production-style security project** that detects and blocks malicious file uploads using **defense-in-depth** techniques. This project demonstrates how real-world applications protect against **extension spoofing, MIME confusion, and known malware signatures**.

---

## 📌 Features

* ✅ Secure file upload handling (Flask)
* ✅ File size limits
* ✅ Extension allow-listing
* ✅ **MIME ↔ Extension validation** using `libmagic`
* ✅ **YARA-based malware signature detection**
* ✅ Quarantine mechanism for suspicious files
* ✅ Structured **security logging & audit trail**
* ✅ Safe testing using EICAR and shell-based samples

---

## 🏗️ Architecture Overview

```
Client
  │
  ▼
Upload Endpoint
  │
  ├─ Extension validation
  ├─ MIME type detection (magic bytes)
  ├─ Extension ↔ MIME consistency check
  ├─ YARA signature scan
  ├─ Logging & audit trail
  │
  ├─ Clean → uploads/
  └─ Malicious → quarantine/
```

---

## 📂 Project Structure

```
malicious-file-upload-detector/
├── app.py
├── requirements.txt
├── rules/
│   └── malware.yar
├── templates/
│   └── upload.html
├── uploads/
├── quarantine/
├── logs/
│   └── security.log
└── README.md
```

---

## ⚙️ Setup Instructions

### 1️⃣ Clone Repository

```bash
git clone https://github.com/yourusername/malicious-file-upload-detector.git
cd malicious-file-upload-detector
```

### 2️⃣ Create Virtual Environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3️⃣ Install System Dependencies

```bash
sudo apt update
sudo apt install -y libmagic1 yara
```

### 4️⃣ Install Python Dependencies

```bash
pip install -r requirements.txt
```

### 5️⃣ Run the Application

```bash
python app.py
```

Open browser:

```
http://127.0.0.1:5000
```

---

## 🧪 Testing Guide

### I have included test files folder cointaing real and fake files so feel free to check the functionality

## 🔐 Threat Model & Security Notes

### Covered Threats

* Extension spoofing (`.exe → .pdf`)
* Script-based malware
* Known malware signatures
* MIME confusion attacks

### Limitations

* Does not detect zero-day malware
* No dynamic/sandbox execution
* No macro or encrypted PDF analysis

> These limitations are **intentional** and documented as part of the threat model.

---


## 🚀 Future Enhancements

* Dockerization
* Rate limiting & abuse prevention
* Hash-based reputation checks
* PDF macro analysis
* Sandbox execution (advanced)

---

## ⚠️ Disclaimer

This project is for **educational and defensive security purposes only**. No real malware is included. All test samples are safe.

---

## ⭐ If you found this useful

Give this repo a ⭐ and feel free to fork or contribute!
