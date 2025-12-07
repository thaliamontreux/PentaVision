# PentaVision Attendance & Recording Platform

This project is a web-based system for managing attendance and video recordings using facial recognition, secure authentication (passkeys/2FA), and pluggable cloud storage providers.

## Quick start (development)

1. Create and activate a virtual environment (recommended):

   ```bash
   python -m venv .venv
   # Windows PowerShell
   .venv\\Scripts\\Activate.ps1
   ```

2. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

3. Run the development server:

   ```bash
   python run.py
   ```

4. Open the app in your browser:
 
   - [http://127.0.0.1:5000/](http://127.0.0.1:5000/) (root)
   - [http://127.0.0.1:5000/health](http://127.0.0.1:5000/health) (basic health check)

## Configuration (early stage)

Configuration is read from environment variables. At this stage, the key settings are:

- `APP_SECRET_KEY` – secret key for Flask sessions.
- `USER_DB_URL` – SQLAlchemy URL for the user/auth database.
- `FACE_DB_URL` – SQLAlchemy URL for the facial recognition database.
- `RECORD_DB_URL` – SQLAlchemy URL for the recordings/metadata database.

These will be wired into the graphical installer and database layer as the project progresses.
