# 🔒 Cloud Misconfiguration Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/FastAPI-0.115-009688?style=for-the-badge&logo=fastapi&logoColor=white"/>
  <img src="https://img.shields.io/badge/Amazon_AWS-232F3E?style=for-the-badge&logo=amazonaws&logoColor=white"/>
  <img src="https://img.shields.io/badge/Docker-2496ED?style=for-the-badge&logo=docker&logoColor=white"/>
  <img src="https://img.shields.io/badge/SQLite-003B57?style=for-the-badge&logo=sqlite&logoColor=white"/>
  <img src="https://img.shields.io/badge/License-MIT-F7DF1E?style=for-the-badge"/>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Boto3-SDK-FF9900?style=for-the-badge&logo=amazonaws&logoColor=white"/>
  <img src="https://img.shields.io/badge/SQLAlchemy-ORM-D71F00?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Pydantic-Data_Validation-E92063?style=for-the-badge&logo=python&logoColor=white"/>
  <img src="https://img.shields.io/badge/Uvicorn-ASGI-499848?style=for-the-badge&logo=gunicorn&logoColor=white"/>
  <img src="https://img.shields.io/badge/CIS-Benchmarks-FF0000?style=for-the-badge&logoColor=white"/>
</p>

> AWS cloud security tool that automatically detects misconfigurations based on **CIS Benchmarks**. Inspired by industry tools like **Prowler** and **ScoutSuite**.

---

## 🎯 What does it detect?

| Scanner | Checks | Severity |
|--------|--------|-----------|
| 🪣 S3 Buckets | Block Public Access disabled, public ACLs | CRITICAL |
| 🔒 Security Groups | SSH/RDP/DB ports open to the world (0.0.0.0/0) | CRITICAL / HIGH |
| 👤 IAM | Unrotated keys +90 days, users without MFA | CRITICAL / HIGH |
| 🔐 Encryption | EBS volumes, RDS instances and S3 without encryption at rest | CRITICAL / HIGH |

---

## 🏗️ Architecture

```text
cloud-misconfig-scanner/
├── app/
│   ├── scanners/
│   │   ├── s3_scanner.py          # S3 public bucket detection
│   │   ├── sg_scanner.py          # Security Group analysis
│   │   ├── iam_scanner.py         # IAM key rotation & MFA checks
│   │   └── encryption_scanner.py  # Encryption at rest validation
│   ├── api/
│   │   └── routes.py              # FastAPI REST endpoints
│   ├── database/
│   │   ├── models.py              # SQLAlchemy models
│   │   └── db.py                  # SQLite connection & session
│   └── main.py                    # App entrypoint
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
└── .env.example
```

---

## 🚀 Getting Started

### Option 1 — Local Setup

```bash
git clone https://github.com/VladimirRamirez07/cloud-misconfig-scanner.git
cd cloud-misconfig-scanner

# Create and activate virtual environment
python -m venv venv
source venv/bin/activate        # Linux/Mac
.\venv\Scripts\Activate         # Windows

# Install dependencies
pip install -r requirements.txt

# Configure environment variables
cp .env.example .env

# Run the API
uvicorn app.main:app --port 8080
```

### Option 2 — Docker

```bash
docker-compose up --build
```

Once running, access the interactive API docs at: **http://localhost:8080/docs**

---

## 📡 API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/api/v1/scan/s3` | Scan S3 buckets for public exposure |
| `POST` | `/api/v1/scan/security-groups` | Scan Security Groups for open ports |
| `POST` | `/api/v1/scan/iam` | Scan IAM users for key rotation & MFA |
| `POST` | `/api/v1/scan/encryption` | Scan EBS, RDS & S3 for missing encryption |
| `POST` | `/api/v1/scan/all` | Run full scan across all services |
| `GET` | `/api/v1/report` | Retrieve historical scan report |

### Request Example

```bash
curl -X POST http://localhost:8080/api/v1/scan/all \
  -H "Content-Type: application/json" \
  -d '{
    "aws_access_key": "YOUR_ACCESS_KEY",
    "aws_secret_key": "YOUR_SECRET_KEY",
    "region": "us-east-1"
  }'
```

### Response Example

```json
{
  "total_findings": 10,
  "summary": {
    "CRITICAL": 5,
    "HIGH": 5,
    "MEDIUM": 0,
    "LOW": 0
  },
  "findings": [
    {
      "resource_id": "demo-bucket-public-01",
      "scan_type": "s3",
      "severity": "CRITICAL",
      "finding": "Block Public Access is not enabled | Public ACL detected: READ",
      "recommendation": "Enable S3 Block Public Access across all configurations",
      "cis_benchmark": "CIS AWS 2.1.5 - S3 Block Public Access"
    }
  ]
}
```

---

## 🛡️ CIS Benchmarks Implemented

| Benchmark | Description |
|-----------|-------------|
| CIS AWS 1.1 | Do not use root account for programmatic access |
| CIS AWS 1.4 | Rotate IAM access keys every 90 days |
| CIS AWS 1.14 | Enable MFA for all IAM users |
| CIS AWS 2.1.1 | Enable default encryption on S3 buckets |
| CIS AWS 2.1.5 | Enable S3 Block Public Access |
| CIS AWS 2.2.1 | Ensure EBS volumes are encrypted |
| CIS AWS 2.3.1 | Ensure RDS instances are encrypted at rest |
| CIS AWS 5.2 | Do not allow SSH access from 0.0.0.0/0 |
| CIS AWS 5.3 | Review unrestricted Security Group rules |

---

## 🧰 Tech Stack

| Technology | Purpose |
|------------|---------|
| **Python 3.11** | Core language |
| **FastAPI** | REST API framework |
| **Boto3** | Official AWS SDK |
| **SQLAlchemy** | ORM for database management |
| **SQLite** | Lightweight findings persistence |
| **Pydantic** | Data validation & serialization |
| **Uvicorn** | ASGI server |
| **Docker** | Containerization |

---

## ⚠️ Demo Mode

No AWS credentials? No problem. The tool automatically runs in **demo mode**, simulating real-world findings for educational and portfolio purposes.

---

## 📄 License

MIT © [VladimirRamirez07](https://github.com/VladimirRamirez07)