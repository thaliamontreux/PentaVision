# Ubuntu 24.04 Server Setup for PentaVision

This guide walks through provisioning an Ubuntu 24.04 **minimal** server and preparing it to run the PentaVision web app, matching the items in `TODO.md` under **System setup & security**.

> Run these commands on your Ubuntu server as a user with `sudo` privileges.

---

## 1. Update the system

```bash
sudo apt update && sudo apt upgrade -y
```

Keep this server regularly updated:

```bash
sudo apt update && sudo apt upgrade -y
```

Consider enabling unattended security upgrades (optional but recommended):

```bash
sudo apt install -y unattended-upgrades
sudo dpkg-reconfigure --priority=low unattended-upgrades
```

---

## 2. Install Apache and core modules

Install Apache and common utilities:

```bash
sudo apt update && sudo apt install -y \
  apache2 apache2-utils \
  libapache2-mod-security2 \
  libapache2-mod-evasive \
  libapache2-mod-php php-mysql \
  ufw
```

Enable and start Apache on boot:

```bash
sudo systemctl enable --now apache2
```

### 2.1 Basic hardening

Disable the default site if you plan to use a dedicated vhost later:

```bash
sudo a2dissite 000-default.conf
sudo systemctl reload apache2
```

Disable directory listing globally:

```bash
sudo a2dismod autoindex
sudo systemctl reload apache2
```

Enable useful modules:

```bash
sudo a2enmod rewrite ssl headers
sudo systemctl reload apache2
```

You can later add a dedicated virtual host for the PentaVision app (proxying to Gunicorn/UWSGI or using WSGI directly) as needed.

---

## 3. Install MariaDB and secure it

Install MariaDB server:

```bash
sudo apt update && sudo apt install -y mariadb-server
```

Secure the installation (set root password, remove test DB, etc.):

```bash
sudo mysql_secure_installation
```

Follow the prompts to:

- Set a strong root password.
- Remove anonymous users.
- Disallow remote root login if appropriate.
- Remove test database.

Enable and start MariaDB on boot:

```bash
sudo systemctl enable --now mariadb
```

You can create separate databases and users for **users**, **faces**, and **recordings** later; this repo provides the schemas and the app expects 3 different connection URLs.

---

## 4. Install language runtimes and tools

Install Python and common tooling:

```bash
sudo apt update && sudo apt install -y \
  python3 python3-venv python3-pip \
  git curl vim
```

If you plan to use PHP modules beyond what is already installed (for Apache/PHP pages):

```bash
sudo apt install -y php-cli php-curl php-xml php-zip
```

If you plan to use Node.js for any frontend build steps, install Node (example using `nodejs` from Ubuntu):

```bash
sudo apt install -y nodejs npm
```

> You can also install a more recent Node.js via NodeSource, nvm, or similar if needed.

---

## 5. Install additional multimedia / AI dependencies

For video processing and OpenCV-based functionality:

```bash
sudo apt update && sudo apt install -y \
  ffmpeg \
  python3-opencv
```

Python packages such as `face-recognition` (which depends on dlib) are installed via `pip` in the project virtualenv, not system-wide. See the project `README.md` for app-level Python deps.

---

## 6. Configure UFW firewall

Allow only the necessary ports (80/443 for HTTP/HTTPS, and 22 for SSH):

```bash
sudo ufw allow 22/tcp
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
sudo ufw status verbose
```

Make sure you have SSH access before enabling UFW, or you may lock yourself out.

---

## 7. Install Fail2ban (intrusion prevention)

Install Fail2ban:

```bash
sudo apt update && sudo apt install -y fail2ban
```

Copy the default jail configuration as a local override and adjust if needed:

```bash
sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
```

At minimum, ensure `ssh` jail is enabled and tune ban times as desired. Then restart Fail2ban:

```bash
sudo systemctl enable --now fail2ban
```

---

## 8. Ensure services start on boot

Confirm key services are enabled:

```bash
sudo systemctl enable apache2
sudo systemctl enable mariadb
sudo systemctl enable fail2ban
```

You can verify status:

```bash
systemctl status apache2
systemctl status mariadb
systemctl status fail2ban
```

---

## 9. Next steps: deploying the app

Once the server is prepared:

1. Clone this repository onto the server.
2. Create a Python virtualenv and install the app requirements:

   ```bash
   cd /opt/pentavision   # or your chosen path
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

3. Configure the app (e.g. via the web installer once it is exposed through Apache/WSGI or a reverse proxy).
4. Add a systemd service and Apache virtual host or reverse proxy for production.

These deployment details will be expanded in separate documentation as the project evolves.

## 10. Using the web installer

Once the app is running behind Apache/WSGI or another reverse proxy, you can
use the built-in web installer to complete configuration:

1. Ensure the `.env` file (or environment) includes a strong `APP_SECRET_KEY`.
2. Browse to the `/install` URL over HTTPS.
3. Follow the wizard to configure the three databases (UserDB, FaceDB, RecordDB)
   and test the connections.
4. Create the initial admin account and confirm installer finalization.

After successful installation the installer is locked and should no longer be
reachable in normal operation.
