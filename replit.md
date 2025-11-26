# Mustee's Secure Password Manager

## Overview
This is a secure desktop password manager application built with Python and Tkinter. It provides encrypted storage for passwords with a master password authentication system.

## Purpose
- Securely store and manage passwords using strong encryption (Fernet/PBKDF2)
- Generate random or custom passwords
- Auto-lock after inactivity
- Clipboard monitoring and automatic clearing for security
- Import/export passwords (CSV format)

## Project Architecture

### Core Components
- **GUI Framework**: Python Tkinter (desktop GUI application)
- **Encryption**: `cryptography` library with Fernet symmetric encryption
- **Key Derivation**: PBKDF2HMAC with SHA-256 (200,000 iterations)
- **Clipboard Management**: `pyperclip` for clipboard operations

### File Structure
```
.
├── core/
│   └── mAA.py          # Main application file
├── requirements.txt     # Python dependencies
├── .gitignore          # Git ignore rules
└── replit.md           # This documentation
```

### Data Files (Auto-generated, not in version control)
- `secret.key.encrypted` - Encrypted master password verification file
- `salt.salt` - Salt for key derivation
- `passwords.dat` - Encrypted password storage

## Features
1. **Master Password Protection**: First-time setup creates a master password with strength validation
2. **Password Generation**: 
   - Random password generator
   - Custom password generator with phrase-based options
3. **Password Management**: View, edit, delete saved passwords
4. **Security Features**:
   - Auto-lock after 5 minutes of inactivity
   - Clipboard auto-clear after 30 seconds
   - Password-like content detection and monitoring
5. **Import/Export**: CSV format support

## Dependencies
- Python 3.11
- `cryptography>=41.0.0` - Encryption and key derivation
- `pyperclip>=1.8.0` - Clipboard operations (optional but recommended)

## Running the Application
The application runs in VNC mode (desktop GUI) on Replit. The workflow is configured to start automatically when you run the project.

**Command**: `python core/mAA.py`

## Security Notes
- Master password cannot be recovered if forgotten
- All passwords are encrypted using Fernet (symmetric encryption)
- Key derivation uses PBKDF2HMAC with 200,000 iterations for brute-force resistance
- Sensitive files are excluded from version control

## Recent Changes (November 26, 2025)
- Initial Replit environment setup
- Installed Python 3.11 and dependencies
- Created requirements.txt for dependency management
- Configured VNC workflow for GUI display
- Added comprehensive .gitignore for Python project
- Created project documentation

## User Preferences
- None specified yet

## Technical Details
- **Display**: VNC (Virtual Network Computing) for GUI rendering
- **Auto-lock Interval**: 5 minutes (300,000 ms)
- **Clipboard Clear Delay**: 30 seconds (30,000 ms)
- **Default Password Length**: 16 characters
