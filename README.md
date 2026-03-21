# NetGuard — Wi-Fi Security Auditor

A full-stack web app that audits your Wi-Fi network setup and gives you an instant security score with actionable fix recommendations.

![NetGuard](https://img.shields.io/badge/status-active-brightgreen) ![Python](https://img.shields.io/badge/python-3.13-blue) ![Next.js](https://img.shields.io/badge/next.js-16-black)

## Features

- **Manual audit** — answer 8 questions about your router config and get an instant security score
- **Live network scan** — uses nmap to scan your local network, detect connected devices, and check open ports on your gateway
- **Color-coded findings** — critical, warning, notice, and pass severity levels with actionable recommendations
- **Security score** — 0–100 score with Secure / At risk / Vulnerable grades

## Tech Stack

**Frontend** — Next.js 16, React, Tailwind CSS

**Backend** — Python, FastAPI, nmap

## Getting Started

### Prerequisites
- Python 3.10+
- Node.js 18+
- nmap installed ([download here](https://nmap.org/download.html))

### Backend

```bash
cd /path/to/project
pip install fastapi uvicorn pydantic python-multipart
python -m uvicorn main:app --reload --port 8000
```

API docs available at: http://127.0.0.1:8000/docs

### Frontend

```bash
cd frontend
npm install
npm run dev
```

App available at: http://localhost:3000

## API Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/` | Health check |
| POST | `/audit/manual` | Score from user-supplied config |
| POST | `/audit/scan` | Live nmap scan of local network |
| GET | `/subnet/detect` | Auto-detect local subnet |

## Project Structure

```
WifiScanner/
├── main.py              # FastAPI backend
├── requirements.txt     # Python dependencies
├── frontend/            # Next.js app
│   └── app/
│       └── page.tsx     # Main UI
└── README.md
```

## License

MIT
