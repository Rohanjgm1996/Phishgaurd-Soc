# 🛡️ PhishGuard SOC

**AI-Powered Phishing Analysis Platform for SOC Analysts**

[![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688?style=flat-square&logo=fastapi)](https://fastapi.tiangolo.com)
[![React](https://img.shields.io/badge/React-18-61DAFB?style=flat-square&logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.4-3178C6?style=flat-square&logo=typescript)](https://typescriptlang.org)
[![Python](https://img.shields.io/badge/Python-3.12-3776AB?style=flat-square&logo=python)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg?style=flat-square)](LICENSE)

---

> **⚠️ Defensive Use Only**
> PhishGuard SOC is built exclusively for defensive security analysis, SOC lab use, and
> educational purposes. It does not contain malware, credential stealers, or offensive
> tooling. All analysis is read-only and static — no uploaded content is executed.

---

## ✨ Overview

PhishGuard SOC is a full-stack phishing analysis platform that allows SOC analysts to:

- 📧 **Analyze `.eml` email files** — headers, body, URLs, SPF/DKIM/DMARC
- 📎 **Inspect attachments** — macros, archive contents, PDF objects, PE headers
- 🔍 **YARA + ClamAV scanning** — pattern and signature-based detection
- 📊 **Risk scoring engine** — weighted score with human-readable explanations
- 🗂️ **IOC extraction** — URLs, domains, IPs, hashes, email addresses
- 🗺️ **MITRE ATT&CK mapping** — automatic technique tagging
- 📄 **JSON + HTML reports** — export-ready analyst reports
- 🖥️ **Premium dark UI** — glassmorphism dashboard with Framer Motion animations

---

## 🖼️ Screenshots

> *Replace these placeholders with actual screenshots after running the app.*

| Login Page | Dashboard |
|---|---|
| ![Login](docs/screenshots/login.png) | ![Dashboard](docs/screenshots/dashboard.png) |

| Upload & Analyze | Analysis Report |
|---|---|
| ![Upload](docs/screenshots/upload.png) | ![Report](docs/screenshots/report.png) |

---

## 🏗️ Architecture

```
phishguard-soc/
├── backend/                   # FastAPI Python backend
│   ├── app/
│   │   ├── main.py            # Application entry point
│   │   ├── api/               # Route handlers (auth, analyze, reports)
│   │   ├── analyzers/         # Analysis engines (email, macros, YARA, ClamAV…)
│   │   ├── core/              # Config, scoring, security, utils
│   │   ├── models/            # SQLAlchemy models, Pydantic schemas
│   │   ├── reports/           # JSON + HTML report builders
│   │   └── services/          # Business logic (auth, analysis orchestration)
│   └── tests/                 # pytest test suite
├── frontend/                  # React + Vite + TypeScript frontend
│   └── src/
│       ├── components/        # Reusable UI components
│       ├── pages/             # Login, Dashboard, Upload, Result, History
│       ├── hooks/             # useAuth context
│       ├── lib/               # API client, utilities
│       └── types/             # TypeScript types
├── rules/                     # YARA detection rules
├── samples/                   # Test samples (benign only)
├── Dockerfile
└── docker-compose.yml
```

**Tech Stack:**
- **Backend:** FastAPI, Python 3.12, SQLAlchemy (async), SQLite, pyjwt, passlib
- **Analysis:** oletools (VBA macros), python-magic, pypdf, yara-python, pefile, BeautifulSoup
- **Frontend:** React 18, Vite, TypeScript, Tailwind CSS, Framer Motion, Recharts, lucide-react
- **Infrastructure:** Docker, docker-compose, ClamAV (optional)

---

## 🚀 Quick Start

### Prerequisites
- Python 3.11+
- Node.js 18+
- (Optional) ClamAV daemon for signature scanning

### 1. Clone the repository
```bash
git clone https://github.com/yourusername/phishguard-soc.git
cd phishguard-soc
```

### 2. Backend setup
```bash
cd backend

# Create virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy and configure environment
cp .env.example .env
# Edit .env — at minimum set a strong SECRET_KEY

# Run the backend
uvicorn app.main:app --reload --port 8000
```

### 3. Frontend setup
```bash
cd frontend

# Install dependencies
npm install

# Run development server
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## 🐳 Docker (Recommended)

### Standard (backend only, no ClamAV)
```bash
# Copy and configure environment
cp backend/.env.example .env

# Build and start
docker compose up --build
```

### With ClamAV (virus scanning enabled)
```bash
# Enable ClamAV in .env
echo "CLAMAV_ENABLED=true" >> .env

# Start with ClamAV profile (first run downloads ~300MB of signatures)
docker compose --profile clamav up --build
```

### Development mode (with hot-reload frontend)
```bash
docker compose --profile dev up --build
```

Access:
- **App:** http://localhost:8000
- **API Docs:** http://localhost:8000/docs
- **Dev frontend:** http://localhost:5173

---

## 🔑 Demo Credentials

> **⚠️ Change these immediately in any non-demo deployment!**

| Field    | Value       |
|----------|-------------|
| Username | `admin`     |
| Password | `Admin@123` |

Configure via `.env`:
```env
DEMO_ADMIN_USERNAME=admin
DEMO_ADMIN_PASSWORD=Admin@123
SECRET_KEY=your-very-long-random-secret-key-here
```

---

## 📡 API Reference

All endpoints require JWT authentication (except `/api/auth/login`).

| Method | Endpoint                     | Description                   |
|--------|------------------------------|-------------------------------|
| POST   | `/api/auth/login`            | Login, returns JWT token      |
| POST   | `/api/auth/logout`           | Logout (token discard)        |
| GET    | `/api/auth/me`               | Current user info             |
| POST   | `/api/analyze/email`         | Analyze `.eml` file           |
| POST   | `/api/analyze/file`          | Analyze any attachment        |
| GET    | `/api/report/{id}`           | Full analysis detail (JSON)   |
| GET    | `/api/report/{id}/json`      | Download JSON report file     |
| GET    | `/api/report/{id}/html`      | View HTML report              |
| PATCH  | `/api/report/{id}/notes`     | Update analyst notes          |
| GET    | `/api/history`               | Paginated analysis history    |
| GET    | `/api/dashboard`             | Dashboard stats               |
| GET    | `/api/health`                | Health check                  |

### Example: Login + Analyze
```bash
# 1. Login
TOKEN=$(curl -s -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@123"}' | jq -r .access_token)

# 2. Analyze an email
curl -X POST http://localhost:8000/api/analyze/email \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@suspicious_email.eml"

# 3. Get the full report
curl http://localhost:8000/api/report/<analysis_id> \
  -H "Authorization: Bearer $TOKEN"
```

---

## 🔬 Analysis Features

### Email Analysis (`.eml`)
- SPF, DKIM, DMARC result extraction
- Sender/Reply-To domain mismatch detection
- Display name spoofing (brand impersonation)
- URL extraction from plain text and HTML body
- Link text vs. href mismatch detection
- Shortened URL detection (bit.ly, tinyurl, etc.)
- IP-based URL detection
- HTML form detection
- Urgency / credential theft language detection
- Full attachment recursive analysis

### Attachment / File Analysis
- True file type detection (magic bytes via python-magic)
- Double extension detection (`invoice.pdf.exe`)
- VBA macro analysis via oletools:
  - Auto-exec macro detection
  - Suspicious keyword flagging
  - Obfuscation detection
- Archive inspection (ZIP, RAR — no extraction)
- Password-protected archive detection
- PDF static analysis (`/JS`, `/Launch`, embedded objects)
- Basic PE executable checks
- YARA rule scanning
- ClamAV signature scanning (optional)

### Scoring Engine
| Rule                     | Score |
|--------------------------|-------|
| SPF Fail                 | +15   |
| Reply-To Mismatch        | +10   |
| Display Name Spoof       | +15   |
| Credential Theft Wording | +10   |
| IP-Based URL             | +20   |
| Link Text Mismatch       | +15   |
| Shortened URL            | +10   |
| Macro-Enabled Office     | +20   |
| Auto-Exec Macro          | +30   |
| Obfuscated VBA           | +25   |
| Embedded Executable      | +35   |
| Password-Protected Archive| +20  |
| Suspicious PDF Action    | +20   |
| YARA Match               | +50   |
| ClamAV Hit               | +70   |

**Verdicts:** Benign (0–24) · Suspicious (25–49) · Likely Phishing (50–79) · Malicious (80+)

---

## 🧪 Running Tests

```bash
cd backend
source .venv/bin/activate
pytest tests/ -v
```

---

## 🔧 YARA Rules

Custom YARA rules live in `rules/`. Add `.yar` files and restart the backend — they are compiled on startup.

Two rule sets are included:
- `rules/phishing_rules.yar` — email body and HTML patterns
- `rules/attachment_rules.yar` — macro, PE, and obfuscation patterns

---

## 🔮 Future Improvements

- [ ] VirusTotal API integration for hash lookups
- [ ] Bulk upload / batch analysis
- [ ] Webhook output for SIEM (Wazuh, Splunk, ELK)
- [ ] Analyst role management and audit log
- [ ] `.msg` Outlook file support
- [ ] URL detonation sandbox integration
- [ ] OpenAI/Claude-powered natural language analysis summary
- [ ] REST API for custom YARA rule CRUD
- [ ] Email notification on high-risk verdicts
- [ ] Multi-tenancy support

---

## ⚖️ Disclaimer

PhishGuard SOC is intended strictly for:
- Defensive security research
- SOC analyst training and tooling
- Lab and educational environments

It must **not** be used to:
- Create phishing infrastructure
- Bypass security controls
- Analyze samples without authorization

Always obtain proper authorization before analyzing any content.

---

## 📄 License

MIT License — see [LICENSE](LICENSE) for details.

---

*Built with ❤️ for the SOC community*
