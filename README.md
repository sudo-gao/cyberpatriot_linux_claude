# 🐧 CyberPatriot Linux Security Checklist (Claude)

> A comprehensive security hardening checklist for CyberPatriot competitions on Linux systems. Items are ordered from highest to lowest point value.
> Consider using gedit in place of nano for a smoother text interface

## ⚠️ CRITICAL FIRST STEPS

**DO THESE BEFORE ANYTHING ELSE:**

1. 📖 **Read the README thoroughly** - Contains critical information about required services and authorized users
2. 🔍 **Answer all forensics questions** - Complete BEFORE making system changes
3. 💾 **Take a VM snapshot** - Create a restore point in case something breaks
4. 📝 **Document authorized users and admins** - Write down who should have access according to README

---

## 🎯 High Priority Items (Most Points)

### 1️⃣ User Account Management

#### List All Users
```bash
# View all users
cat /etc/passwd

# View only regular users (UID >= 1000)
awk -F: '$3 >= 1000 {print $1}' /etc/passwd

# View all users with home directories
ls /home/
```

#### Remove Unauthorized Users
```bash
# Delete user and their home directory
sudo userdel -r <username>

# Delete user but keep home directory (if needed for forensics)
sudo userdel <username>

# Verify user was removed
cat /etc/passwd | grep <username>
```

**Instructions:**
- Compare against README authorized users list
- Remove any users not explicitly authorized
- Check both `/etc/passwd` and `/home/` directories

#### Check and Remove Unauthorized Sudoers (do this in terminal or just settings)
```bash
# List all users with sudo privileges
getent group sudo
getent group admin # Ubuntu also uses admin group

# View sudoers file (DO NOT EDIT DIRECTLY)
sudo visudo -c # Check syntax
sudo cat /etc/sudoers
```

Remove from sudo group:
```bash
# Remove user from sudo group
sudo deluser <username> sudo
sudo deluser <username> admin

# Verify removal
groups <username>
```

**Check for additional sudo access:**
```bash
# Check sudoers.d directory for per-user files
ls -la /etc/sudoers.d/
sudo cat /etc/sudoers.d/*

# Remove unauthorized sudoers files
sudo rm /etc/sudoers.d/<filename>
```

⚠️ **VERY RISKY**: Never remove your own user from sudo or you'll lose admin access!

#### Add Missing Authorized Users
```bash
# Create new user (interactive - sets password, creates home dir)
sudo adduser <username>

# Add to sudo group if authorized as admin
sudo usermod -aG sudo <username>

# Verify user was created
id <username>
```

#### Disable/Lock Unnecessary Accounts
```bash
# Lock the root account (best practice)
sudo passwd -l root

# Disable guest login (Ubuntu with LightDM)
sudo sh -c 'printf "[Seat:*]\nallow-guest=false\n" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf'

# Check for and disable other system accounts with shells
awk -F: '($3 < 1000) && ($7 != "/usr/sbin/nologin") && ($7 != "/bin/false") {print $1}' /etc/passwd
```

#### Check for Unauthorized UID 0 Accounts
```bash
# Only root should have UID 0
awk -F: '($3 == 0) {print $1}' /etc/passwd
```
- If any user besides `root` has UID 0, that's a backdoor!
- Remove that account immediately

#### Secure User Home Directories
```bash
# Check home directory permissions
ls -la /home/

# Fix permissions (owner only)
sudo chmod 750 /home/<username>
sudo chown <username>:<username> /home/<username>
```

---

### 2️⃣ Password Policies

#### Install Password Quality Library
```bash
# Install PAM password quality module
sudo apt-get update
sudo apt-get install libpam-pwquality -y
```

#### Configure Password Complexity Requirements
```bash
# Edit PAM password configuration
sudo nano /etc/pam.d/common-password
```

Find the line with `pam_pwquality.so` or `pam_unix.so` and modify/add:
```
password requisite pam_pwquality.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=2
```

**Parameters explained:**
- `retry=3` - Allow 3 attempts to set password
- `minlen=8` - Minimum 8 characters
- `difok=3` - At least 3 characters different from old password
- `ucredit=-1` - Require at least 1 uppercase letter
- `lcredit=-1` - Require at least 1 lowercase letter
- `dcredit=-1` - Require at least 1 digit
- `ocredit=-1` - Require at least 1 special character
- `maxrepeat=2` - No more than 2 repeated characters

#### Configure Password Aging
```bash
# Edit login definitions
sudo nano /etc/login.defs
```

Set these values:
```
PASS_MAX_DAYS 90
PASS_MIN_DAYS 1
PASS_WARN_AGE 7
PASS_MIN_LEN 8
```

**Apply to existing users:**
```bash
# Apply password aging to all regular users
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    sudo chage -M 90 -m 1 -W 7 "$user"
    echo "Updated password policy for $user"
done

# Check a specific user's password policy
sudo chage -l <username>
```

#### Force Password Changes on Next Login (if needed)
```bash
# Force user to change password on next login
sudo passwd -e <username>
```

#### Set Strong Passwords for All Users
```bash
# Change password for a user
sudo passwd <username>
```
- Make sure all user passwords meet complexity requirements
- Don't use default passwords like "password123" or "cyberpatriot"

---

### 3️⃣ System Updates and Patches

#### Update Package Lists and Upgrade All Packages
```bash
# Update package repository lists
sudo apt-get update

# Upgrade all installed packages
sudo apt-get upgrade -y

# Full distribution upgrade (more aggressive)
sudo apt-get dist-upgrade -y

# Remove unnecessary packages
sudo apt-get autoremove -y
sudo apt-get autoclean
```

**Instructions:**
- Run updates early - they can take 10-30+ minutes
- Usually worth significant points
- ⚠️ **RISKY**: May require system restart or take about a billion years
- Check for kernel updates: `uname -r` then reboot if kernel was updated

#### Enable Automatic Security Updates
```bash
# Install unattended-upgrades
sudo apt-get install unattended-upgrades -y

# Configure automatic updates
sudo dpkg-reconfigure -plow unattended-upgrades
# Select "Yes" when prompted

# Verify it's enabled
sudo systemctl status unattended-upgrades
```

#### Check for Available Updates
```bash
# Check what updates are available
apt list --upgradable

# Check for security updates specifically
sudo unattended-upgrade --dry-run -d
```

---

### 4️⃣ Firewall Configuration

#### Install and Enable UFW (Uncomplicated Firewall)
```bash
# Install UFW (usually pre-installed on Ubuntu)
sudo apt-get install ufw -y

# Set default policies
sudo ufw default deny incoming
sudo ufw default allow outgoing

# Enable UFW
sudo ufw enable

# Check status
sudo ufw status verbose
```

**Warning:** The system will prompt that this may disrupt SSH connections. If you're doing this remotely, allow SSH first!

#### Allow Required Services
```bash
# Allow SSH (do this BEFORE enabling firewall if accessing remotely!)
sudo ufw allow ssh
# Or specific port: sudo ufw allow 22/tcp

# Allow other services as needed per README
sudo ufw allow 80/tcp # HTTP
sudo ufw allow 443/tcp # HTTPS
sudo ufw allow 21/tcp # FTP (only if required)
sudo ufw allow 3306/tcp # MySQL (only if required)

# Allow service by name
sudo ufw allow apache
sudo ufw allow nginx
```

#### Review and Remove Unnecessary Firewall Rules
```bash
# List all rules with numbers
sudo ufw status numbered

# Delete a rule by number
sudo ufw delete <number>
```

#### Enable Logging
```bash
# Enable firewall logging
sudo ufw logging on
sudo ufw logging medium
```

---

### 5️⃣ Remove Prohibited Software

#### List Installed Packages
```bash
# List all installed packages
dpkg -l

# Search for specific software
dpkg -l | grep -i <software_name>

# Or use apt
apt list --installed | grep -i <software_name>
```

#### Common Prohibited Software to Remove

**Hacking/Pentesting Tools:**
```bash
# Network analyzers
sudo apt-get purge wireshark wireshark-* -y

# Port scanners
sudo apt-get purge nmap zenmap -y

# Password crackers
sudo apt-get purge john john-data ophcrack -y
sudo apt-get purge hydra hydra-gtk -y

# Other pentesting tools
sudo apt-get purge metasploit* -y
sudo apt-get purge aircrack-ng -y
sudo apt-get purge netcat netcat-* nc -y
sudo apt-get purge nikto -y
sudo apt-get purge sqlmap -y

# Sniffers
sudo apt-get purge tcpdump -y
sudo apt-get purge ettercap* -y
```

**Games:**
```bash
# Remove game packages
sudo apt-get purge gnome-games -y
sudo apt-get purge kde-games -y
sudo apt-get purge aisleriot -y
sudo apt-get purge gnome-mahjongg -y
sudo apt-get purge gnome-mines -y
sudo apt-get purge gnome-sudoku -y
```

**P2P/Torrent Software:**
```bash
sudo apt-get purge transmission transmission-* -y
sudo apt-get purge deluge deluge-* -y
sudo apt-get purge frostwire -y
sudo apt-get purge vuze -y
```

**Unauthorized Remote Access:**
```bash
# Only remove if not required by README!
sudo apt-get purge teamviewer -y
sudo apt-get purge anydesk -y
sudo apt-get purge tightvncserver -y
sudo apt-get purge vnc4server -y
```

**Clean up after removal:**
```bash
sudo apt-get autoremove -y
sudo apt-get autoclean
```

#### Find and Remove Prohibited Media Files
```bash
# Find audio files
sudo find /home -name "*.mp3" 2>/dev/null
sudo find /home -name "*.wav" 2>/dev/null
sudo find /home -name "*.flac" 2>/dev/null

# Find video files
sudo find /home -name "*.mp4" 2>/dev/null
sudo find /home -name "*.avi" 2>/dev/null
sudo find /home -name "*.mkv" 2>/dev/null
sudo find /home -name "*.mov" 2>/dev/null

# Find image files (be careful - some may be legitimate)
sudo find /home -name "*.jpg" 2>/dev/null
sudo find /home -name "*.png" 2>/dev/null

# Delete a file
sudo rm /path/to/file

# Or delete multiple files of same type
sudo find /home -name "*.mp3" -type f -delete
```

⚠️ **Be careful:** Some media files may be legitimate or required! Check README first.

---

### 6️⃣ Service Management

#### List All Running Services
```bash
# List all services (systemd)
sudo systemctl list-units --type=service --state=running

# List all services (including inactive)
sudo systemctl list-units --type=service --all

# Check specific service status
sudo systemctl status <service_name>
```

#### Disable and Stop Unnecessary Services

**Common Services to Disable (unless required by README):**

```bash
# Telnet (VERY insecure - almost always disable)
sudo systemctl stop telnet.socket
sudo systemctl disable telnet.socket

# FTP (insecure - disable unless required)
sudo systemctl stop vsftpd
sudo systemctl disable vsftpd

# Apache/nginx (disable if not web server)
sudo systemctl stop apache2
sudo systemctl disable apache2
sudo systemctl stop nginx
sudo systemctl disable nginx

# MySQL/PostgreSQL (disable if not database server)
sudo systemctl stop mysql
sudo systemctl disable mysql
sudo systemctl stop postgresql
sudo systemctl disable postgresql

# Samba (Windows file sharing - disable unless required)
sudo systemctl stop smbd
sudo systemctl disable smbd
sudo systemctl stop nmbd
sudo systemctl disable nmbd

# NFS (disable unless required)
sudo systemctl stop nfs-server
sudo systemctl disable nfs-server

# SNMP (can leak information)
sudo systemctl stop snmpd
sudo systemctl disable snmpd

# Print services (disable if not print server)
sudo systemctl stop cups
sudo systemctl disable cups

# Bluetooth (disable if not needed)
sudo systemctl stop bluetooth
sudo systemctl disable bluetooth

# Avahi (zeroconf/mDNS - potential info leak)
sudo systemctl stop avahi-daemon
sudo systemctl disable avahi-daemon
```

**Verify service is stopped:**
```bash
sudo systemctl status <service_name>
```

⚠️ **VERY RISKY**: Disabling wrong services can break required functionality and cost points!

**Services to NEVER disable:**
- `ssh` / `sshd` (if you need remote access)
- `networking` / `NetworkManager`
- `systemd-*` services
- `dbus`
- Services required by README

#### Secure SSH (If Required)
```bash
# Edit SSH configuration
sudo nano /etc/ssh/sshd_config
```

**Recommended SSH hardening:**
```bash
# Disable root login
PermitRootLogin no

# Disable password authentication (use keys only - RISKY for competition!)
# PasswordAuthentication no # Usually keep this as 'yes' for competition

# Disable empty passwords
PermitEmptyPasswords no

# Limit authentication attempts
MaxAuthTries 3

# Set login grace time
LoginGraceTime 60

# Disable X11 forwarding (unless needed)
X11Forwarding no

# Only allow specific users (optional)
AllowUsers <user1> <user2>

# Use protocol 2 only (should be default)
Protocol 2

# Change default port (advanced)
# Port 2222
```

**Restart SSH after changes:**
```bash
sudo systemctl restart sshd
# Or
sudo service ssh restart
```

⚠️ **VERY RISKY**: Test SSH access before logging out! Wrong config can lock you out.

---

## 🎯 Medium Priority Items (Good Points)

### 7️⃣ File Permissions and Security

#### Find World-Writable Files
```bash
# Find world-writable files (excluding /proc, /sys)
sudo find / -path /proc -prune -o -path /sys -prune -o -type f -perm -002 -ls 2>/dev/null

# Fix world-writable files (be careful!)
sudo chmod o-w /path/to/file
```

#### Find Files with No Owner
```bash
# Find files with no user owner
sudo find / -nouser -ls 2>/dev/null

# Find files with no group owner
sudo find / -nogroup -ls 2>/dev/null
```

#### Secure Sensitive Files
```bash
# Secure /etc/passwd and /etc/shadow
sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow
sudo chown root:root /etc/passwd
sudo chown root:shadow /etc/shadow

# Secure /etc/group and /etc/gshadow
sudo chmod 644 /etc/group
sudo chmod 640 /etc/gshadow

# Secure SSH keys
sudo chmod 600 ~/.ssh/id_rsa
sudo chmod 644 ~/.ssh/id_rsa.pub
sudo chmod 700 ~/.ssh
```

#### Find and Remove SUID/SGID Binaries
```bash
# Find SUID files (execute as file owner)
sudo find / -perm -4000 -type f -ls 2>/dev/null

# Find SGID files (execute as file group)
sudo find / -perm -2000 -type f -ls 2>/dev/null

# Remove SUID/SGID bit if not needed (be VERY careful!)
sudo chmod u-s /path/to/file # Remove SUID
sudo chmod g-s /path/to/file # Remove SGID
```

⚠️ **VERY RISKY**: Some programs require SUID to function (sudo, passwd, etc.)

**Common legitimate SUID files:**
- `/usr/bin/sudo`
- `/usr/bin/passwd`
- `/usr/bin/su`
- `/usr/bin/mount`
- `/usr/bin/umount`

#### Check Cron Jobs for Malicious Tasks
```bash
# View system cron jobs
ls -la /etc/cron.*
cat /etc/crontab

# View user cron jobs
sudo crontab -l -u <username>

# Check for all users
for user in $(cut -f1 -d: /etc/passwd); do 
    echo "=== $user crontab ===" 
    sudo crontab -u $user -l 2>/dev/null
done
```

**Remove suspicious cron jobs:**
```bash
# Edit crontab for user
sudo crontab -e -u <username>

# Delete cron job file
sudo rm /etc/cron.d/<suspicious_file>
```

---

### 8️⃣ Network Security

#### Disable IPv6 (If Not Needed)
```bash
# Edit sysctl config
sudo nano /etc/sysctl.conf
```

Add these lines:
```
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

Apply changes:
```bash
sudo sysctl -p
```

#### Configure Network Security Parameters
```bash
# Edit sysctl config
sudo nano /etc/sysctl.conf
```

Add/modify these lines:
```bash
# IP Forwarding (disable unless router)
net.ipv4.ip_forward = 0

# Disable source packet routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

# Disable ICMP redirect acceptance
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0

# Disable secure ICMP redirect acceptance
net.ipv4.conf.all.secure_redirects = 0

# Enable bad error message protection
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1

# Enable TCP SYN cookies (DDoS protection)
net.ipv4.tcp_syncookies = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1

# Ignore ICMP ping requests (optional)
# net.ipv4.icmp_echo_ignore_all = 1
```

Apply changes:
```bash
sudo sysctl -p
```

#### Check for Listening Ports
```bash
# Show all listening ports
sudo netstat -tulpn

# Or with ss (newer)
sudo ss -tulpn

# Check for specific port
sudo lsof -i :PORT_NUMBER
```

**Investigate suspicious listening ports:**
- Unexpected high ports
- Services you don't recognize
- Connections to unknown IPs

---

### 9️⃣ Audit and Logging

#### Install and Configure Auditd
```bash
# Install audit daemon
sudo apt-get install auditd audispd-plugins -y

# Enable and start auditd
sudo systemctl enable auditd
sudo systemctl start auditd

# Check status
sudo systemctl status auditd
```

#### Configure Audit Rules
```bash
# View current rules
sudo auditctl -l

# Edit audit rules
sudo nano /etc/audit/rules.d/audit.rules
```

**Add basic audit rules:**
```bash
# Monitor changes to passwd file
-w /etc/passwd -p wa -k passwd_changes

# Monitor changes to group file
-w /etc/group -p wa -k group_changes

# Monitor changes to shadow file
-w /etc/shadow -p wa -k shadow_changes

# Monitor sudo usage
-w /etc/sudoers -p wa -k sudoers_changes
-w /var/log/sudo.log -p wa -k sudo_log

# Monitor SSH configuration
-w /etc/ssh/sshd_config -p wa -k sshd_config_changes

# Monitor login/logout events
-w /var/log/lastlog -p wa -k lastlog_changes
-w /var/run/faillock/ -p wa -k faillock_changes
```

Reload rules:
```bash
sudo augenrules --load
sudo systemctl restart auditd
```

#### Configure Rsyslog
```bash
# Install rsyslog (usually pre-installed)
sudo apt-get install rsyslog -y

# Enable and start
sudo systemctl enable rsyslog
sudo systemctl start rsyslog

# Check logs
sudo tail -f /var/log/syslog
sudo tail -f /var/log/auth.log
```

---

### 🔟 Additional Security Measures

#### Install and Configure AppArmor
```bash
# Install AppArmor (usually pre-installed on Ubuntu)
sudo apt-get install apparmor apparmor-utils -y

# Check AppArmor status
sudo aa-status

# Enable AppArmor
sudo systemctl enable apparmor
sudo systemctl start apparmor

# Put profiles in enforce mode
sudo aa-enforce /etc/apparmor.d/*
```

#### Remove Compilers (If Not Needed)
```bash
# Check if compilers are installed
which gcc
which g++
which cc

# Remove compilers (only if README doesn't require them!)
sudo apt-get purge gcc g++ make -y
```

⚠️ **RISKY**: May break dependencies or required functionality!

#### Configure Banners and Login Messages
```bash
# Edit pre-login banner
sudo nano /etc/issue.net
```

Add warning message:
```
***************************************************************************
                            NOTICE TO USERS

This computer system is for authorized use only. Unauthorized access is
prohibited and may be subject to criminal prosecution.
***************************************************************************
```

```bash
# Edit post-login message
sudo nano /etc/motd
```

#### Disable USB Storage (Optional, Advanced)
```bash
# Prevent USB storage devices from being used
sudo nano /etc/modprobe.d/usb-storage.conf
```

Add:
```
install usb-storage /bin/true
```

⚠️ **RISKY**: May be needed for competition!

#### Check for Rootkits
```bash
# Install rkhunter
sudo apt-get install rkhunter -y

# Update database
sudo rkhunter --update

# Run scan
sudo rkhunter --check --skip-keypress
```

#### Secure Shared Memory
```bash
# Edit fstab
sudo nano /etc/fstab
```

Add this line:
```
tmpfs /run/shm tmpfs defaults,noexec,nosuid 0 0
```

Remount:
```bash
sudo mount -o remount /run/shm
```

---

## 🎯 Lower Priority Items (Still Worth Points)

### 1️⃣1️⃣ Application-Specific Security

#### Secure Apache (If Running)
```bash
# Edit Apache config
sudo nano /etc/apache2/apache2.conf
```

Add/modify:
```apache
# Disable directory listing
Options -Indexes

# Hide Apache version
ServerTokens Prod
ServerSignature Off

# Disable unnecessary modules
sudo a2dismod status
sudo a2dismod autoindex

# Enable security modules
sudo a2enmod headers
sudo a2enmod ssl
```

Restart Apache:
```bash
sudo systemctl restart apache2
```

#### Secure MySQL/MariaDB (If Running)
```bash
# Run security script
sudo mysql_secure_installation
```

Answer "Yes" to all prompts:
- Set root password
- Remove anonymous users
- Disallow root login remotely
- Remove test database
- Reload privilege tables

#### Secure PHP (If Running)
```bash
# Edit PHP configuration
sudo nano /etc/php/7.4/apache2/php.ini # Adjust version numbe


