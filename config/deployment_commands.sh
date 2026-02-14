#!/bin/bash
# ============================================================
# COMPLETE DEPLOYMENT GUIDE - nwscan.mooo.com
# Network Security Tools Platform on Azure VM (Ubuntu 24.04)
# ============================================================
# HOW TO USE: Copy and paste each section step by step.
# DO NOT run this entire file at once.
# ============================================================


# ────────────────────────────────────────────────────────────
# SECTION 1: CONNECT TO YOUR AZURE VM
# ────────────────────────────────────────────────────────────

# SSH into your VM (replace with your actual IP)
ssh tintin@20.74.83.15

# If using SSH key file:
ssh -i ~/Downloads/your-key.pem tintin@20.74.83.15


# ────────────────────────────────────────────────────────────
# SECTION 2: SYSTEM UPDATE & PACKAGES
# ────────────────────────────────────────────────────────────

# Update system
sudo apt update && sudo apt upgrade -y

# Install required packages
sudo apt install -y python3 python3-pip python3-venv nmap nginx git curl wget


# ────────────────────────────────────────────────────────────
# SECTION 3: PROJECT DIRECTORY SETUP
# ────────────────────────────────────────────────────────────

# Create project folder
mkdir -p ~/website
cd ~/website

# Create subdirectory structure
mkdir -p static/css static/js static/images templates docs

# Verify structure
ls -la


# ────────────────────────────────────────────────────────────
# SECTION 4: PYTHON VIRTUAL ENVIRONMENT
# ────────────────────────────────────────────────────────────

# Create virtual environment
python3 -m venv venv

# Activate virtual environment
source venv/bin/activate

# Verify activation (should show venv path)
which python3

# Install all required Python packages
pip install flask python-nmap flask-limiter flask-sqlalchemy reportlab --break-system-packages

# Verify installed packages
pip list


# ────────────────────────────────────────────────────────────
# SECTION 5: UPLOAD YOUR FILES
# ────────────────────────────────────────────────────────────

# From your LOCAL machine, upload files via SCP:
# (Run these commands on YOUR computer, not the VM)

# Upload app.py
scp app.py tintin@20.74.83.15:~/website/

# Upload templates
scp templates/base.html    tintin@20.74.83.15:~/website/templates/
scp templates/index.html   tintin@20.74.83.15:~/website/templates/
scp templates/scanner.html tintin@20.74.83.15:~/website/templates/
scp templates/history.html tintin@20.74.83.15:~/website/templates/
scp templates/cv.html      tintin@20.74.83.15:~/website/templates/

# Upload CSS
scp static/css/style.css tintin@20.74.83.15:~/website/static/css/

# OR upload entire folder at once:
scp -r website/ tintin@20.74.83.15:~/


# ────────────────────────────────────────────────────────────
# SECTION 6: CRITICAL NMAP PERMISSION FIX
# ────────────────────────────────────────────────────────────
# WITHOUT THIS, NMAP RETURNS EMPTY RESULTS FROM FLASK!

# Set Linux capabilities on nmap binary
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap

# Verify capabilities are set
getcap /usr/bin/nmap
# Expected output: /usr/bin/nmap cap_net_bind_service,cap_net_admin,cap_net_raw=eip

# Test nmap works without sudo
nmap -sT -T4 8.8.8.8 -p 53,443
# Should show ports 53 and 443 as open

# Test from Python (most important test!)
cd ~/website && source venv/bin/activate
python3 -c "
import nmap
nm = nmap.PortScanner()
nm.scan('8.8.8.8', '53,443', '-sT -T4')
print('Hosts:', nm.all_hosts())
if nm.all_hosts():
    print('State:', nm['8.8.8.8'].state())
    print('Protocols:', nm['8.8.8.8'].all_protocols())
    print('SUCCESS - Nmap working from Python!')
else:
    print('FAIL - Nmap returned no hosts')
"


# ────────────────────────────────────────────────────────────
# SECTION 7: TEST FLASK APP MANUALLY
# ────────────────────────────────────────────────────────────

cd ~/website
source venv/bin/activate

# Test run (Ctrl+C to stop)
python3 app.py

# In a second terminal, test it's responding:
curl http://localhost:5000/
# Should return HTML


# ────────────────────────────────────────────────────────────
# SECTION 8: SYSTEMD SERVICE SETUP
# ────────────────────────────────────────────────────────────

# Create the service file
sudo nano /etc/systemd/system/website.service

# --- Paste this content into nano ---
# [Unit]
# Description=Flask Website Application
# After=network.target
#
# [Service]
# User=tintin
# WorkingDirectory=/home/tintin/website
# Environment="PATH=/home/tintin/website/venv/bin"
# ExecStart=/home/tintin/website/venv/bin/python3 app.py
# Restart=always
# RestartSec=10
#
# [Install]
# WantedBy=multi-user.target
# --- End of content ---

# Save: Ctrl+X, Y, Enter

# Load and enable the service
sudo systemctl daemon-reload
sudo systemctl enable website
sudo systemctl start website

# Check it's running
sudo systemctl status website

# View logs
sudo journalctl -u website -f


# ────────────────────────────────────────────────────────────
# SECTION 9: NGINX CONFIGURATION
# ────────────────────────────────────────────────────────────

# Create nginx config
sudo nano /etc/nginx/sites-available/website

# --- Paste this content into nano ---
# server {
#     listen 80;
#     server_name nwscan.mooo.com;
#
#     location / {
#         proxy_pass         http://127.0.0.1:5000;
#         proxy_set_header Host              $host;
#         proxy_set_header X-Real-IP         $remote_addr;
#         proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
#         proxy_read_timeout 600s;
#     }
#
#     location /static {
#         alias /home/tintin/website/static;
#         expires 30d;
#     }
# }
# --- End of content ---

# Enable the site
sudo ln -s /etc/nginx/sites-available/website /etc/nginx/sites-enabled/

# Remove default site
sudo rm -f /etc/nginx/sites-enabled/default

# Test nginx config
sudo nginx -t
# Must say: syntax is ok / test is successful

# Restart nginx
sudo systemctl restart nginx
sudo systemctl enable nginx

# Test it works
curl http://nwscan.mooo.com/


# ────────────────────────────────────────────────────────────
# SECTION 10: SSL/HTTPS SETUP (Let's Encrypt)
# ────────────────────────────────────────────────────────────

# Install Certbot
sudo apt install certbot python3-certbot-nginx -y

# Get SSL certificate (replace with your email)
sudo certbot --nginx -d nwscan.mooo.com \
     --email your-email@example.com \
     --agree-tos --no-eff-email

# When asked about redirects, choose option 2 (Redirect HTTP → HTTPS)

# Test auto-renewal
sudo certbot renew --dry-run

# Verify HTTPS works
curl https://nwscan.mooo.com/


# ────────────────────────────────────────────────────────────
# SECTION 11: AZURE NETWORK SECURITY GROUP (NSG)
# ────────────────────────────────────────────────────────────

# In Azure Portal → Your VM → Networking → Add inbound rules:
# Port 22  (SSH)   - Your IP only (for security)
# Port 80  (HTTP)  - Any
# Port 443 (HTTPS) - Any
# Port 5000 - DENY (Flask should only be accessed via Nginx)


# ────────────────────────────────────────────────────────────
# SECTION 12: DYNAMIC DNS (No-IP)
# ────────────────────────────────────────────────────────────

# 1. Go to https://www.noip.com and create a free account
# 2. Create hostname: nwscan.mooo.com
# 3. Set it to point to your Azure VM public IP (e.g. 20.74.83.15)
# 4. Check your VM's public IP:
curl https://api.ipify.org
# 5. Update No-IP hostname to match this IP if different


# ────────────────────────────────────────────────────────────
# SECTION 13: DAILY MAINTENANCE COMMANDS
# ────────────────────────────────────────────────────────────

# Restart all services
sudo systemctl restart website nginx

# View application logs (live stream)
sudo journalctl -u website -f

# View last 50 log lines
sudo journalctl -u website -n 50 --no-pager

# View nginx access log
sudo tail -f /var/log/nginx/nwscan_access.log

# View nginx error log
sudo tail -f /var/log/nginx/nwscan_error.log

# Check all services status
sudo systemctl status website nginx

# Check disk space
df -h

# Check memory usage
free -h

# Check running Python processes
ps aux | grep python3

# Test site is responding
curl -I https://nwscan.mooo.com

# Activate virtual environment (for manual Python work)
cd ~/website && source venv/bin/activate

# Backup SQLite database
cp ~/website/instance/scans.db ~/backups/scans_$(date +%Y%m%d_%H%M%S).db

# Update Python packages
cd ~/website && source venv/bin/activate
pip install --upgrade flask python-nmap flask-limiter flask-sqlalchemy reportlab


# ────────────────────────────────────────────────────────────
# SECTION 14: TROUBLESHOOTING
# ────────────────────────────────────────────────────────────

# PROBLEM: Scanner shows DOWN / no ports found
# SOLUTION: Re-run the nmap setcap command
sudo setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip /usr/bin/nmap
# Then ensure you use -sT (not -sS) in app.py scan arguments

# PROBLEM: Port 5000 already in use
sudo fuser -k 5000/tcp
sudo systemctl restart website

# PROBLEM: 502 Bad Gateway in nginx
# Flask is not running. Check:
sudo systemctl status website
sudo journalctl -u website -n 30

# PROBLEM: Service won't start (check exact error)
sudo journalctl -u website -n 50 --no-pager

# PROBLEM: SSL certificate expired or error
sudo certbot renew
sudo systemctl restart nginx

# PROBLEM: Website not accessible from internet
# Check Azure NSG allows port 80 and 443
# Check nginx is running: sudo systemctl status nginx
# Check Flask is running: sudo systemctl status website

# PROBLEM: Database error / corruption
rm ~/website/instance/scans.db
sudo systemctl restart website
# Database will be recreated automatically

# PROBLEM: Permission denied errors
# Fix file permissions
sudo chown -R tintin:tintin ~/website
chmod 755 ~/website

# TEST: Manually verify nmap from Python
cd ~/website && source venv/bin/activate
python3 -c "
import nmap
nm = nmap.PortScanner()
nm.scan('8.8.8.8', '53,443', '-sT -T4')
print('Hosts:', nm.all_hosts())
print('State:', nm['8.8.8.8'].state() if nm.all_hosts() else 'N/A')
if nm.all_hosts() and 'tcp' in nm['8.8.8.8']:
    for port, data in nm['8.8.8.8']['tcp'].items():
        print(f'  Port {port}: {data[\"state\"]} ({data.get(\"name\",\"\")})')
"

# TEST: Check all files are in place
ls -la ~/website/
ls -la ~/website/templates/
ls -la ~/website/static/css/


# ────────────────────────────────────────────────────────────
# SECTION 15: QUICK REFERENCE
# ────────────────────────────────────────────────────────────

# File locations:
# /home/tintin/website/app.py                       Main Flask app
# /home/tintin/website/templates/                   HTML templates
# /home/tintin/website/static/css/style.css         Stylesheet
# /home/tintin/website/instance/scans.db            SQLite database
# /home/tintin/website/venv/                        Python virtual env
# /etc/nginx/sites-available/website                Nginx config
# /etc/systemd/system/website.service               Systemd service
# /etc/letsencrypt/live/nwscan.mooo.com/            SSL certificates
# /var/log/nginx/nwscan_access.log                  Access logs
# /var/log/nginx/nwscan_error.log                   Error logs

# Default credentials (CHANGE THESE!):
# URL:      https://nwscan.mooo.com
# Username: admin
# Password: SecurePass123!

echo "Deployment reference loaded successfully!"
