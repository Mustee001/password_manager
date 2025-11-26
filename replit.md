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

## Running the Application
The application runs as a full-stack web app on Replit:
- Frontend: Vite dev server on port 5000
- Backend: Flask API on port 5001

**Command**: `bash run.sh`

## Security Notes
- Master password cannot be recovered if forgotten
- All passwords are encrypted at rest using Fernet
- Key derivation uses 200,000 PBKDF2 iterations
- Sessions auto-expire after inactivity
- Sensitive data files are excluded from version control

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
- Complete rebuild from Tkinter to modern web stack
- New professional branding: "AegisVault - Elite Password Security"
- Mobile-first responsive design
- React frontend with Tailwind CSS
- Flask REST API backend
- JWT-based authentication
- Dark/light theme toggle
- Real-time password strength meter
- Improved password generator with custom phrase support
- JSON import/export functionality

## User Preferences
- Default theme: Dark mode
- Auto-lock timeout: 5 minutes
- Clipboard clear delay: 30 seconds
- Default password length: 16 characters

## Technical Configuration
- **Frontend Port**: 5000 (Vite dev server)
- **Backend Port**: 5001 (Flask API)
- **JWT Expiry**: 30 minutes (auto-refresh at 15 min)
- **Session Timeout**: 5 minutes of inactivity
