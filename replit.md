# AegisVault - Elite Password Security

## Overview
AegisVault is a professional, cross-platform password manager with a modern web interface. It provides military-grade encryption for password storage with a master password authentication system. The application works seamlessly on both desktop and mobile devices.

## Purpose
- Securely store and manage passwords using AES-256 encryption (Fernet/PBKDF2)
- Generate strong random or custom memorable passwords
- Auto-lock after inactivity for enhanced security
- Automatic clipboard clearing for copied passwords
- Import/export passwords in JSON format
- Dark and light theme support

## Project Architecture

### Technology Stack
- **Backend**: Python Flask with JWT authentication
- **Frontend**: React 18 with Vite and Tailwind CSS
- **Encryption**: `cryptography` library with Fernet symmetric encryption
- **Key Derivation**: PBKDF2HMAC with SHA-256 (200,000 iterations)
- **Production Server**: Gunicorn WSGI
- **Rate Limiting**: Flask-Limiter
- **Icons**: Lucide React

### File Structure
```
.
├── server/
│   └── app.py              # Flask API backend
├── client/
│   ├── src/
│   │   ├── App.jsx         # Main React component
│   │   ├── main.jsx        # Entry point
│   │   ├── index.css       # Tailwind styles
│   │   ├── pages/
│   │   │   ├── Login.jsx   # Login/setup page
│   │   │   └── Dashboard.jsx # Main vault interface
│   │   └── utils/
│   │       └── api.js      # API client
│   ├── public/
│   │   └── shield.svg      # App icon
│   ├── index.html          # HTML template
│   ├── vite.config.js      # Vite configuration
│   ├── tailwind.config.js  # Tailwind configuration
│   └── package.json        # Node dependencies
├── data/                   # Encrypted data storage (auto-created)
├── run.sh                  # Startup script
├── build.sh                # Production build script
├── render.yaml             # Render deployment config
├── requirements.txt        # Python dependencies
├── .gitignore             # Git ignore rules
└── replit.md              # This documentation
```

### Data Files (Auto-generated, not in version control)
- `data/master.key.encrypted` - Encrypted master password verification
- `data/salt.salt` - Salt for key derivation
- `data/vault.dat` - Encrypted password storage

## Features

### Security Features
1. **Master Password Protection**: Strong master password with strength validation
2. **Military-Grade Encryption**: AES-256 via Fernet symmetric encryption
3. **Key Derivation**: PBKDF2HMAC with 200,000 iterations for brute-force resistance
4. **Auto-Lock**: Locks after 5 minutes of inactivity
5. **Clipboard Auto-Clear**: Clears copied passwords after 30 seconds
6. **JWT Session Management**: Secure token-based authentication with auto-refresh
7. **Rate Limiting**: Protection against brute-force attacks
8. **Security Headers**: XSS, CSRF, and clickjacking protection

### Password Management
1. **Password Vault**: View, search, edit, and delete saved passwords
2. **Password Generation**:
   - Random generator with customizable length (8-64 chars)
   - Character type options (uppercase, lowercase, numbers, symbols)
   - Custom phrase-based generator for memorable passwords
3. **Strength Meter**: Real-time password strength analysis
4. **Import/Export**: JSON format for data portability

### User Interface
1. **Responsive Design**: Works on mobile, tablet, and desktop
2. **Dark/Light Theme**: Toggle between dark slate and light mode
3. **Modern Design**: Professional teal and gold accent colors
4. **Glassmorphism**: Elegant glass-card effects
5. **Smooth Animations**: Polished transitions and interactions

## API Endpoints

### Authentication
- `GET /api/status` - Check vault initialization status
- `POST /api/auth/setup` - Create new vault with master password
- `POST /api/auth/login` - Unlock vault with master password
- `POST /api/auth/logout` - Lock vault
- `POST /api/auth/refresh` - Refresh JWT token

### Password Management
- `GET /api/passwords` - List all passwords
- `POST /api/passwords` - Add new password entry
- `PUT /api/passwords/<website>` - Update password entry
- `DELETE /api/passwords/<website>` - Delete password entry

### Utilities
- `POST /api/generate` - Generate password (random or custom)
- `POST /api/strength` - Check password strength
- `GET /api/export` - Export all passwords
- `POST /api/import` - Import passwords
- `GET /health` - Health check endpoint

## Running the Application

### Development (Replit)
The application runs as a full-stack web app on Replit:
- Frontend: Vite dev server on port 5000
- Backend: Flask API on port 5001

**Command**: `bash run.sh`

### Production Build
```bash
./build.sh
```

## Deployment Guide

### Option 1: Deploy on Render (Recommended - Free Tier)

Render offers a generous free tier perfect for hosting this application.

#### Step-by-Step Instructions:

1. **Push Code to GitHub**
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   git remote add origin https://github.com/YOUR_USERNAME/aegisvault.git
   git push -u origin main
   ```

2. **Create Render Account**
   - Go to [render.com](https://render.com)
   - Sign up with GitHub for easy integration

3. **Create New Web Service**
   - Click "New" → "Web Service"
   - Connect your GitHub repository
   - Select the `aegisvault` repository

4. **Configure Build Settings**
   - **Name**: `aegisvault` (or your preferred name)
   - **Region**: Choose closest to your location
   - **Branch**: `main`
   - **Runtime**: Python 3
   - **Build Command**: 
     ```
     pip install -r requirements.txt && cd client && npm install && npm run build
     ```
   - **Start Command**: 
     ```
     gunicorn --bind 0.0.0.0:$PORT wsgi:app
     ```

5. **Add Environment Variables**
   - `JWT_SECRET`: Click "Generate" or create a secure random string
   - `PYTHON_VERSION`: `3.11.0`
   - `NODE_VERSION`: `20`

6. **Add Persistent Disk (Important for Data)**
   - Click "Disk" tab
   - **Name**: `aegisvault-data`
   - **Mount Path**: `/data`
   - **Size**: 1 GB (free tier limit)
   
   Then add environment variable:
   - `DATA_DIR`: `/data`

7. **Deploy**
   - Click "Create Web Service"
   - Wait for build to complete (5-10 minutes first time)
   - Your app will be live at `https://aegisvault-XXXXX.onrender.com`

#### Render Free Tier Limitations:
- **Spin-down**: Service sleeps after 15 minutes of inactivity
- **Spin-up delay**: 30-60 seconds when waking up
- **Instance hours**: 750 hours/month
- **Bandwidth**: 100 GB/month

### Option 2: Deploy on Railway (Free Tier)

Railway offers $5 free credit monthly.

1. **Go to [railway.app](https://railway.app)**
2. **Sign up with GitHub**
3. **Create New Project** → "Deploy from GitHub repo"
4. **Select your repository**
5. **Add Variables**:
   - `JWT_SECRET`: Generate a secure random string
   - `DATA_DIR`: `/app/data`
6. **Railway auto-detects Python and builds**

### Option 3: Deploy on Fly.io (Free Tier)

1. **Install Fly CLI**
   ```bash
   curl -L https://fly.io/install.sh | sh
   ```

2. **Login and Launch**
   ```bash
   fly auth login
   fly launch
   ```

3. **Add Persistent Volume**
   ```bash
   fly volumes create aegisvault_data --size 1 --region lax
   ```

4. **Set Secrets**
   ```bash
   fly secrets set JWT_SECRET=$(openssl rand -hex 32)
   fly secrets set DATA_DIR=/data
   ```

5. **Deploy**
   ```bash
   fly deploy
   ```

### Option 4: Deploy on PythonAnywhere (Free Tier)

1. **Create account at [pythonanywhere.com](https://pythonanywhere.com)**
2. **Upload your code** via Git or file upload
3. **Build frontend locally** and upload `client/dist` folder
4. **Configure WSGI** to point to `server/app.py`
5. **Set environment variables** in the dashboard

## Environment Variables

| Variable | Required | Description | Default |
|----------|----------|-------------|---------|
| `JWT_SECRET` | Yes (production) | Secret key for JWT tokens | Auto-generated |
| `DATA_DIR` | No | Directory for encrypted data | `./data` |
| `PORT` | No | Server port | `5001` |
| `FLASK_ENV` | No | Environment mode | `production` |

## Security Notes
- Master password cannot be recovered if forgotten
- All passwords are encrypted at rest using Fernet
- Key derivation uses 200,000 PBKDF2 iterations
- Sessions auto-expire after inactivity
- Sensitive data files are excluded from version control
- Rate limiting protects against brute-force attacks

## Design System

### Color Palette
- **Primary**: Teal (#14b8a6) - Trust and security
- **Accent**: Gold (#d4af37) - Premium and elite
- **Dark Background**: Slate (#0a0f1a to #1e293b)
- **Light Background**: Cool grays (#f1f5f9 to white)

### Typography
- **Font Family**: Inter (Google Fonts)
- **Weights**: 300 (light), 400 (regular), 500 (medium), 600 (semibold), 700 (bold)

## Recent Changes (November 26, 2025)
- Added production deployment configuration (Render, Railway, Fly.io)
- Added Gunicorn WSGI server for production
- Added Flask-Limiter for rate limiting
- Added security headers (XSS, CSRF, Clickjacking protection)
- Added health check endpoint
- Environment variable configuration for production
- Comprehensive deployment documentation

## User Preferences
- Default theme: Dark mode
- Auto-lock timeout: 5 minutes
- Clipboard clear delay: 30 seconds
- Default password length: 16 characters

## Technical Configuration
- **Frontend Port**: 5000 (Vite dev server)
- **Backend Port**: 5001 (Flask API)
- **Production Port**: Configured via `PORT` environment variable
- **JWT Expiry**: 30 minutes (auto-refresh at 15 min)
- **Session Timeout**: 5 minutes of inactivity
- **Rate Limits**: 200 requests/day, 50 requests/hour per IP
