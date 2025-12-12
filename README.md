# 🛡️ CyberPatriot Linux Security Checklist

> **Comprehensive guide for Ubuntu 24.04 & Linux Mint 21 CyberPatriot competitions**  
> Optimized for maximum points | Competition-tested | Prioritized by point value

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

---

## 📋 Table of Contents

- [Critical First Steps](#-critical-first-steps)
- [Quick Point Reference](#-quick-point-reference)
- [High Priority (Most Points)](#-high-priority-most-points)
  - [User Account Management](#1%EF%B8%8F⃣-user-account-management)
  - [Password Policies](#2%EF%B8%8F⃣-password-policies)
  - [System Updates](#3%EF%B8%8F⃣-system-updates--patches)
  - [Firewall Configuration](#4%EF%B8%8F⃣-firewall-configuration)
  - [Remove Prohibited Software](#5%EF%B8%8F⃣-remove-prohibited-software)
  - [Service Management](#6%EF%B8%8F⃣-service-management)
- [Medium Priority](#-medium-priority-good-points)
  - [SSH Hardening](#7%EF%B8%8F⃣-ssh-hardening)
  - [File Permissions](#8%EF%B8%8F⃣-file-permissions--security)
  - [Network Security](#9%EF%B8%8F⃣-network-security)
  - [Account Security](#-account-lockout--security-policies)
- [Standard Priority](#-standard-priority-solid-points)
  - [Audit & Logging](#-audit--logging)
  - [Antivirus](#-antivirus-configuration)
  - [Process & Port Monitoring](#-process--port-monitoring)
- [Additional Hardening](#-additional-hardening-bonus-points)
- [Do NOT Disable List](#-do-not-disable-list)
- [Verification Commands](#-verification-commands)
- [Troubleshooting](#-troubleshooting)

---

## ⚠️ CRITICAL FIRST STEPS

**Complete these BEFORE making ANY changes:**

### 📖 1. Read Everything
```bash
# Open and thoroughly read:
- README.txt / README.desktop (contains authorized users, required services)
- Forensics Questions (answer BEFORE modifying system)
- Scoring Report (if available)
```

### 💾 2. Take a Snapshot
- **VirtualBox:** Machine → Take Snapshot
- **VMware:** VM → Snapshot → Take Snapshot
- Name it: `Initial-Backup-[timestamp]`

### 📝 3. Document Authorized Items
Create a text file with:
```
AUTHORIZED USERS:
- user1 (admin)
- user2 (standard)

REQUIRED SERVICES:
- ssh
- apache2
- mysql

ALLOWED SOFTWARE:
- firefox
- libreoffice
```

---

## 🎯 Quick Point Reference

| Task | Typical Points | Priority |
|------|---------------|----------|
| Remove unauthorized user | 5-10 pts each | 🔴 CRITICAL |
| Remove unauthorized admin | 5-10 pts each | 🔴 CRITICAL |
| Strong password policy | 10-15 pts | 🔴 CRITICAL |
| System updates | 5-10 pts | 🔴 CRITICAL |
| Enable firewall | 5-8 pts | 🔴 CRITICAL |
| Remove prohibited software | 3-5 pts each | 🟠 HIGH |
| Disable unnecessary services | 3-5 pts each | 🟠 HIGH |
| SSH hardening | 5-10 pts | 🟡 MEDIUM |
| File permissions | 2-5 pts each | 🟡 MEDIUM |
| Account lockout policy | 3-5 pts | 🟡 MEDIUM |
| Enable antivirus | 3-5 pts | 🟢 STANDARD |
| Audit logging | 2-4 pts | 🟢 STANDARD |

---

## 🔴 HIGH PRIORITY (MOST POINTS)

### 1️⃣ User Account Management

**Worth 5-10 points per violation - highest point value!**

#### ✅ List All Users
```bash
# View all users
cat /etc/passwd

# View only regular users (UID >= 1000)
awk -F: '$3 >= 1000 {print $1}' /etc/passwd

# List home directories
ls -la /home/
```

#### ✅ Check for UID 0 Accounts (Root Equivalents)
```bash
# Should ONLY show 'root'
awk -F: '($3 == "0") {print $1}' /etc/passwd
```
**If you see any user besides root → REMOVE IMMEDIATELY**

#### ✅ Check for Empty Passwords
```bash
# Should return nothing
sudo awk -F: '($2 == "") {print $1}' /etc/shadow
```

#### ✅ Remove Unauthorized Users
```bash
# Remove user and home directory
sudo userdel -r <username>

# Verify deletion
cat /etc/passwd | grep <username>
```

#### ✅ Remove Unauthorized Admins
```bash
# List sudo group members
getent group sudo

# Remove from sudo group
sudo deluser <username> sudo

# Check for sudoers.d entries
ls -la /etc/sudoers.d/
sudo cat /etc/sudoers.d/*

# Remove suspicious files
sudo rm /etc/sudoers.d/<suspicious_file>
```

#### ✅ Add Missing Authorized Users
```bash
# Create user
sudo adduser <username>

# Add to sudo group (ONLY if authorized as admin)
sudo usermod -aG sudo <username>
```

#### ✅ Lock Root Account
```bash
sudo passwd -l root

# Verify locked
sudo passwd -S root  # Should show 'L'
```

#### ✅ Disable Guest Login (Ubuntu/LightDM)
```bash
sudo sh -c 'printf "[Seat:*]\nallow-guest=false\n" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf'
```

---

### 2️⃣ Password Policies

**Worth 10-15 points total - always heavily weighted!**

#### ✅ Install Password Quality Library
```bash
sudo apt install libpam-pwquality -y
```

#### ✅ Configure Strong Password Requirements
Edit `/etc/pam.d/common-password`:
```bash
sudo nano /etc/pam.d/common-password
```

Find the line with `pam_pwquality.so` and replace it with:
```
password requisite pam_pwquality.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=2
```

**Explanation:**
- `retry=3` - Allow 3 password attempts
- `minlen=8` - Minimum 8 characters
- `difok=3` - At least 3 characters different from old password
- `ucredit=-1` - Require 1 uppercase letter
- `lcredit=-1` - Require 1 lowercase letter
- `dcredit=-1` - Require 1 digit
- `ocredit=-1` - Require 1 special character
- `maxrepeat=2` - No more than 2 repeated characters

#### ✅ Configure Password Aging
Edit `/etc/login.defs`:
```bash
sudo nano /etc/login.defs
```

Set these values:
```
PASS_MAX_DAYS   90
PASS_MIN_DAYS   10
PASS_WARN_AGE   7
PASS_MIN_LEN    8
```

Apply to existing users:
```bash
for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
    sudo chage -M 90 -m 10 -W 7 "$user"
done
```

Apply to new users:
```bash
sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/default/useradd
sudo sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   10/' /etc/default/useradd
```

#### ✅ Configure Password History (Prevent Reuse)
Edit `/etc/pam.d/common-password`:
```bash
sudo nano /etc/pam.d/common-password
```

Add this line:
```
password required pam_pwhistory.so remember=5
```

#### ✅ Configure Account Lockout Policy
Edit `/etc/pam.d/common-auth`:
```bash
sudo nano /etc/pam.d/common-auth
```

Add before `pam_unix.so`:
```
auth required pam_faillock.so preauth silent audit deny=5 unlock_time=1800
auth [default=die] pam_faillock.so authfail audit deny=5 unlock_time=1800
```

Edit `/etc/pam.d/common-account`:
```bash
sudo nano /etc/pam.d/common-account
```

Add:
```
account required pam_faillock.so
```

**This locks accounts for 30 minutes after 5 failed attempts**

#### ✅ Change Weak Passwords
```bash
# Force password change on next login
sudo passwd -e <username>

# Or set strong password immediately
sudo passwd <username>
```

---

### 3️⃣ System Updates & Patches

**Worth 5-10 points - critical security measure**

#### ✅ Update All Packages
```bash
sudo apt update
sudo apt upgrade -y
sudo apt dist-upgrade -y
sudo apt autoremove -y
sudo apt autoclean
```

⚠️ **If kernel updated → REBOOT REQUIRED**

Check if reboot needed:
```bash
[ -f /var/run/reboot-required ] && echo "Reboot required" || echo "No reboot needed"
```

#### ✅ Enable Automatic Security Updates
```bash
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades
```

Select "Yes" when prompted.

---

### 4️⃣ Firewall Configuration

**Worth 5-8 points - always included**

#### ✅ Install and Enable UFW
```bash
sudo apt install ufw -y
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
```

#### ✅ Allow Only Required Services
```bash
# Common required services:
sudo ufw allow ssh        # or: sudo ufw allow 22/tcp
sudo ufw allow 80/tcp     # HTTP (if web server required)
sudo ufw allow 443/tcp    # HTTPS (if web server required)

# Check README for other required services
```

#### ✅ Enable Firewall Logging
```bash
sudo ufw logging medium
```

#### ✅ Verify UFW Status
```bash
sudo ufw status verbose
```

Expected output:
```
Status: active
Logging: on (medium)
Default: deny (incoming), allow (outgoing), disabled (routed)
```

---

### 5️⃣ Remove Prohibited Software

**Worth 3-5 points each - can add up quickly**

#### ✅ Remove Hacking/Pentesting Tools
```bash
sudo apt purge wireshark wireshark-qt wireshark-common -y
sudo apt purge nmap zenmap -y
sudo apt purge john john-data -y
sudo apt purge hydra hydra-gtk -y
sudo apt purge metasploit-framework -y
sudo apt purge aircrack-ng -y
sudo apt purge tcpdump -y
sudo apt purge nikto -y
sudo apt purge sqlmap -y
sudo apt purge netcat netcat-traditional netcat-openbsd -y
sudo apt purge ophcrack -y
sudo apt purge kismet -y
```

#### ✅ Remove P2P/Torrent Software
```bash
sudo apt purge transmission* -y
sudo apt purge deluge* -y
sudo apt purge frostwire -y
sudo apt purge vuze -y
sudo apt purge ktorrent -y
sudo apt purge bittorrent -y
```

#### ✅ Remove Games
```bash
sudo apt purge gnome-games* -y
sudo apt purge aisleriot gnome-mahjongg gnome-mines gnome-sudoku -y
sudo apt purge solitaire -y
sudo apt purge freecell -y
```

#### ✅ Remove Media Players (if prohibited)
```bash
# Check README first!
sudo apt purge vlc -y
sudo apt purge audacious -y
```

#### ✅ Clean Up
```bash
sudo apt autoremove -y
sudo apt autoclean
```

#### ✅ Search for Prohibited Media Files
```bash
# Music files
sudo find /home -type f \( -iname "*.mp3" -o -iname "*.wav" -o -iname "*.flac" \)

# Video files
sudo find /home -type f \( -iname "*.mp4" -o -iname "*.avi" -o -iname "*.mkv" \)

# Remove if found (example)
sudo rm /path/to/prohibited/file
```

#### ✅ Check for Hidden Files
```bash
sudo find /home -name ".*" -type f
```

---

### 6️⃣ Service Management

**Worth 3-5 points each - significant point source**

#### ✅ List All Running Services
```bash
sudo systemctl list-units --type=service --state=running
sudo systemctl list-units --type=service --all | grep enabled
```

#### ✅ Disable Insecure/Unnecessary Services

⚠️ **ONLY disable if NOT required by README!**

```bash
# Telnet (insecure remote access)
sudo systemctl disable --now telnet.socket

# FTP (insecure file transfer)
sudo systemctl disable --now vsftpd

# Web servers (disable if not required)
sudo systemctl disable --now apache2
sudo systemctl disable --now nginx

# Databases (disable if not required)
sudo systemctl disable --now mysql
sudo systemctl disable --now postgresql

# File sharing
sudo systemctl disable --now smbd nmbd  # Samba
sudo systemctl disable --now nfs-server
sudo systemctl disable --now rpcbind

# Printing
sudo systemctl disable --now cups

# Bluetooth (desktop environments)
sudo systemctl disable --now bluetooth

# Avahi (network discovery)
sudo systemctl disable --now avahi-daemon

# SNMP (network monitoring)
sudo systemctl disable --now snmpd
```

#### ✅ Verify Service Stopped
```bash
sudo systemctl status <service_name>
```

---

## 🟡 MEDIUM PRIORITY (GOOD POINTS)

### 7️⃣ SSH Hardening

**Worth 5-10 points - if SSH is required**

⚠️ **ONLY modify if SSH is a REQUIRED service!**

Edit `/etc/ssh/sshd_config`:
```bash
sudo nano /etc/ssh/sshd_config
```

**Recommended Settings:**
```
# Protocol and Authentication
Protocol 2
PermitRootLogin no
PermitEmptyPasswords no
PasswordAuthentication yes
PubkeyAuthentication yes

# Limits
MaxAuthTries 3
MaxSessions 2
LoginGraceTime 60

# Security
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitUserEnvironment no

# Logging
SyslogFacility AUTH
LogLevel INFO

# Connection timeout
ClientAliveInterval 300
ClientAliveCountMax 2

# Restrict users (optional - be careful!)
# AllowUsers user1 user2
# AllowGroups sshusers
```

**Restart SSH:**
```bash
sudo systemctl restart sshd
```

⚠️ **Test SSH connection in new terminal BEFORE closing current session!**

---

### 8️⃣ File Permissions & Security

**Worth 2-5 points each**

#### ✅ Find World-Writable Files
```bash
sudo find / -type f -perm -002 ! -path "/proc/*" ! -path "/sys/*" -ls 2>/dev/null
```

Fix:
```bash
sudo chmod o-w /path/to/file
```

#### ✅ Secure Critical System Files
```bash
# /etc/passwd - should be 644
sudo chmod 644 /etc/passwd
sudo chown root:root /etc/passwd

# /etc/shadow - should be 640
sudo chmod 640 /etc/shadow
sudo chown root:shadow /etc/shadow

# /etc/group - should be 644
sudo chmod 644 /etc/group
sudo chown root:root /etc/group

# /etc/gshadow - should be 640
sudo chmod 640 /etc/gshadow
sudo chown root:shadow /etc/gshadow
```

#### ✅ Check SUID/SGID Files
```bash
# Find SUID files
sudo find / -perm -4000 -type f ! -path "/proc/*" ! -path "/sys/*" -ls 2>/dev/null

# Find SGID files
sudo find / -perm -2000 -type f ! -path "/proc/*" ! -path "/sys/*" -ls 2>/dev/null
```

⚠️ **Only remove SUID/SGID if you're CERTAIN the file is malicious!**

Common legitimate SUID binaries:
- `/usr/bin/sudo`
- `/usr/bin/passwd`
- `/usr/bin/su`
- `/bin/ping`

#### ✅ Find Files with No Owner
```bash
sudo find / -nouser -o -nogroup 2>/dev/null
```

Assign owner:
```bash
sudo chown root:root /path/to/file
```

---

### 9️⃣ Network Security

**Worth 3-8 points combined**

#### ✅ Disable IPv6 (if not needed)

Check README first - some scenarios require IPv6!

Edit `/etc/sysctl.conf`:
```bash
sudo nano /etc/sysctl.conf
```

Add:
```
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
```

Apply:
```bash
sudo sysctl -p
```

#### ✅ Harden Network Parameters
Edit `/etc/sysctl.conf`:
```bash
sudo nano /etc/sysctl.conf
```

Add:
```
# IP Forwarding (disable unless router)
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Source routing (disable)
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# ICMP redirects (disable)
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0

# Send redirects (disable)
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0

# SYN cookies (enable)
net.ipv4.tcp_syncookies = 1

# Log suspicious packets
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1

# Ignore ICMP ping
net.ipv4.icmp_echo_ignore_all = 0  # Set to 1 to disable ping

# Ignore broadcast pings
net.ipv4.icmp_echo_ignore_broadcasts = 1

# TCP timestamps (disable for privacy)
net.ipv4.tcp_timestamps = 0
```

Apply:
```bash
sudo sysctl -p
```

#### ✅ Configure Hosts Files
Check `/etc/hosts.allow` and `/etc/hosts.deny`:
```bash
sudo nano /etc/hosts.deny
```

Add (if needed):
```
ALL: ALL
```

```bash
sudo nano /etc/hosts.allow
```

Add only required services:
```
sshd: 192.168.1.0/24
```

---

### 🔒 Account Lockout & Security Policies

**Worth 3-5 points**

Already covered in [Password Policies](#2%EF%B8%8F⃣-password-policies) section above.

---

## 🟢 STANDARD PRIORITY (SOLID POINTS)

### 🔍 Audit & Logging

**Worth 2-4 points**

#### ✅ Install Auditd
```bash
sudo apt install auditd audispd-plugins -y
sudo systemctl enable auditd
sudo systemctl start auditd
```

#### ✅ Configure Audit Rules
Edit `/etc/audit/rules.d/audit.rules`:
```bash
sudo nano /etc/audit/rules.d/audit.rules
```

Add:
```
# Monitor passwd changes
-w /etc/passwd -p wa -k passwd_changes
-w /etc/shadow -p wa -k shadow_changes
-w /etc/group -p wa -k group_changes
-w /etc/gshadow -p wa -k gshadow_changes

# Monitor sudoers
-w /etc/sudoers -p wa -k sudoers_changes
-w /etc/sudoers.d/ -p wa -k sudoers_changes

# Monitor SSH config
-w /etc/ssh/sshd_config -p wa -k sshd_config_changes

# Monitor login/logout
-w /var/log/lastlog -p wa -k logins
-w /var/run/faillock/ -p wa -k logins

# Monitor user/group tools
-w /usr/bin/passwd -p x -k passwd_modification
-w /usr/sbin/groupadd -p x -k group_modification
-w /usr/sbin/useradd -p x -k user_modification
-w /usr/sbin/userdel -p x -k user_modification
```

Reload rules:
```bash
sudo augenrules --load
sudo systemctl restart auditd
```

---

### 🦠 Antivirus Configuration

**Worth 3-5 points**

#### ✅ Install ClamAV
```bash
sudo apt install clamav clamav-daemon -y
```

#### ✅ Update Virus Definitions
```bash
sudo systemctl stop clamav-freshclam
sudo freshclam
sudo systemctl start clamav-freshclam
```

#### ✅ Run System Scan
```bash
# Quick scan of home directories
sudo clamscan -r -i /home

# Full system scan (takes time)
sudo clamscan -r -i --exclude-dir=/proc --exclude-dir=/sys /
```

#### ✅ Enable ClamAV Daemon
```bash
sudo systemctl enable clamav-daemon
sudo systemctl start clamav-daemon
```

---

### 👁️ Process & Port Monitoring

**Worth 2-3 points for finding issues**

#### ✅ Check Running Processes
```bash
ps aux | less
top
htop  # if installed
```

Look for:
- Unusual process names
- Processes running as root unnecessarily
- High CPU/memory usage

#### ✅ Check Listening Ports
```bash
sudo ss -tulpn
# or
sudo netstat -tulpn
```

Verify all listening services are authorized:
- Port 22 (SSH)
- Port 80 (HTTP)
- Port 443 (HTTPS)
- Port 3306 (MySQL)
- etc.

Kill unauthorized processes:
```bash
sudo kill -9 <PID>
```

---

## 🔧 ADDITIONAL HARDENING (BONUS POINTS)

### 🔐 Core Dumps & Kernel Hardening

#### ✅ Disable Core Dumps
Edit `/etc/security/limits.conf`:
```bash
sudo nano /etc/security/limits.conf
```

Add:
```
* hard core 0
```

Edit `/etc/sysctl.conf`:
```bash
sudo nano /etc/sysctl.conf
```

Add:
```
fs.suid_dumpable = 0
kernel.core_uses_pid = 1
```

#### ✅ Additional Kernel Hardening
Add to `/etc/sysctl.conf`:
```
# Restrict dmesg
kernel.dmesg_restrict = 1

# Restrict kernel pointers
kernel.kptr_restrict = 2

# Restrict perf
kernel.perf_event_paranoid = 3

# Restrict kernel logs
kernel.printk = 3 3 3 3

# Restrict access to kernel address
kernel.kptr_restrict = 2
```

Apply:
```bash
sudo sysctl -p
```

---

### 🛡️ AppArmor

#### ✅ Install and Enable AppArmor
```bash
sudo apt install apparmor apparmor-utils apparmor-profiles apparmor-profiles-extra -y
sudo systemctl enable apparmor
sudo systemctl start apparmor
```

#### ✅ Check AppArmor Status
```bash
sudo aa-status
```

#### ✅ Set Profiles to Enforce Mode (carefully!)
```bash
# List profiles
sudo aa-status

# Enforce specific profiles (example)
sudo aa-enforce /etc/apparmor.d/usr.bin.firefox
```

⚠️ **Be careful - enforcing all profiles can break required services!**

---

### 🔍 Rootkit Detection

#### ✅ Install and Run rkhunter
```bash
sudo apt install rkhunter -y
sudo rkhunter --update
sudo rkhunter --propupd
sudo rkhunter --check --skip-keypress
```

Review `/var/log/rkhunter.log` for warnings.

---

### 📢 Login Banners

#### ✅ Configure Pre-Login Banner
Edit `/etc/issue.net`:
```bash
sudo nano /etc/issue.net
```

Add:
```
***************************************************************************
                            NOTICE TO USERS

This computer system is the property of [Organization]. It is for authorized
use only. Users (authorized or unauthorized) have no explicit or implicit
expectation of privacy.

Any or all uses of this system and all files on this system may be intercepted,
monitored, recorded, copied, audited, inspected, and disclosed to authorized
site, law enforcement personnel, as well as authorized officials of other
agencies, both domestic and foreign.

By using this system, the user consents to such interception, monitoring,
recording, copying, auditing, inspection, and disclosure at the discretion
of authorized personnel.

Unauthorized or improper use of this system may result in administrative
disciplinary action and civil and criminal penalties.

By continuing to use this system you indicate your awareness of and consent
to these terms and conditions of use.

LOG OFF IMMEDIATELY if you do not agree to the conditions stated in this warning.
***************************************************************************
```

#### ✅ Enable Banner for SSH (if SSH required)
Edit `/etc/ssh/sshd_config`:
```bash
sudo nano /etc/ssh/sshd_config
```

Add/uncomment:
```
Banner /etc/issue.net
```

Restart SSH:
```bash
sudo systemctl restart sshd
```

---

#
