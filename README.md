🎯 CyberPatriot Checklist (Prioritized)
⚠️ CRITICAL FIRST STEPS

Complete before anything else to avoid breaking the system or losing points:

Read the README thoroughly – essential for knowing required services and authorized users.

Answer all forensics questions before making system changes.

Take a VM snapshot – create a restore point.

Document authorized users and admins – based on README.

🛠️ High Priority Items (Most Points)
1️⃣ User Account Management

List All Users:

cat /etc/passwd  # View all users
awk -F: '$3 >= 1000 {print $1}' /etc/passwd  # View only regular users (UID >= 1000)


This command helps verify which accounts are in the system and what their UID is.

Remove Unauthorized Users:

sudo userdel -r <username>  # Remove user and their home directory
sudo userdel <username>  # Remove user but keep home directory (for forensics)


Verify the user has been deleted by checking /etc/passwd:

cat /etc/passwd | grep <username>


Remove Unauthorized Sudoers:

getent group sudo  # List users with sudo access
sudo visudo -c  # Check sudoers syntax
sudo cat /etc/sudoers  # View sudoers file
sudo deluser <username> sudo  # Remove from sudo group


Add Authorized Users:

sudo adduser <username>  # Create a new user
sudo usermod -aG sudo <username>  # Add to sudo group if authorized


Lock Root Account (Best Practice):

sudo passwd -l root


Disable Guest Login (for Ubuntu with LightDM):

sudo sh -c 'printf "[Seat:*]\nallow-guest=false\n" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf'

2️⃣ Password Policies

Install PAM Password Quality Library:

sudo apt-get install libpam-pwquality -y


Configure Password Complexity:
Edit /etc/pam.d/common-password and modify:

password requisite pam_pwquality.so retry=3 minlen=8 difok=3 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=2


retry=3: Allow 3 attempts for a valid password.

minlen=8: Minimum length of 8 characters.

difok=3: At least 3 characters different from the old password.

ucredit=-1: At least 1 uppercase letter.

lcredit=-1: At least 1 lowercase letter.

dcredit=-1: At least 1 digit.

ocredit=-1: At least 1 special character.

maxrepeat=2: No more than 2 repeated characters.

Configure Password Aging:
Edit /etc/login.defs:

PASS_MAX_DAYS 90
PASS_MIN_DAYS 10
PASS_WARN_AGE 7


Force Password Change:

sudo passwd -e <username>


Change Weak Passwords:

sudo passwd <username>  # Set a strong, secure password

3️⃣ System Updates and Patches

Update System Packages:

sudo apt-get update && sudo apt-get upgrade -y
sudo apt-get dist-upgrade -y  # For full distribution upgrades
sudo apt-get autoremove -y
sudo apt-get autoclean


Note: Run updates as early as possible to secure the system.

Check for Kernel Updates:

uname -r  # Check current kernel version

4️⃣ Firewall Configuration

Install and Enable UFW (Uncomplicated Firewall):

sudo apt-get install ufw -y
sudo ufw default deny incoming  # Block incoming connections
sudo ufw default allow outgoing  # Allow outgoing connections
sudo ufw enable  # Enable UFW
sudo ufw status verbose  # Check UFW status


Allow Required Services:

sudo ufw allow ssh  # Allow SSH
sudo ufw allow 80/tcp  # Allow HTTP
sudo ufw allow 443/tcp  # Allow HTTPS


Enable Firewall Logging:

sudo ufw logging on
sudo ufw logging medium

5️⃣ Remove Prohibited Software

List Installed Packages:

dpkg -l


Remove Unauthorized or Prohibited Software:

sudo apt-get purge <package_name> -y
sudo apt-get autoremove -y  # Clean up after removal
sudo apt-get autoclean


Commonly prohibited software:

Network Analyzers: Wireshark, tcpdump

Pentesting Tools: Nmap, metasploit

Remote Access Tools: TeamViewer, AnyDesk

6️⃣ Service Management

List All Running Services:

sudo systemctl list-units --type=service --state=running
sudo systemctl list-units --type=service --all


Disable Unnecessary Services:

sudo systemctl stop telnet.socket
sudo systemctl disable telnet.socket
sudo systemctl stop apache2  # If not required
sudo systemctl disable apache2


Verify Service Stopped:

sudo systemctl status <service_name>


Ensure Required Services Stay Running:

ssh, networking, dbus, and other critical services should not be disabled unless specified in the README.

7️⃣ Network Security

Disable IPv6 (if not needed):
Edit /etc/sysctl.conf:

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1


Apply changes:

sudo sysctl -p


Configure Network Security Parameters:
Edit /etc/sysctl.conf to harden networking:

net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0

8️⃣ Audit and Logging

Install and Configure Auditd:

sudo apt-get install auditd audispd-plugins -y
sudo systemctl enable auditd
sudo systemctl start auditd


Configure Audit Rules:
Edit /etc/audit/rules.d/audit.rules to monitor critical files:

-w /etc/passwd -p wa -k passwd_changes
-w /etc/group -p wa -k group_changes
-w /etc/shadow -p wa -k shadow_changes

🎯 Medium Priority Items (Good Points)
9️⃣ File Permissions and Security

Find World-Writable Files:

sudo find / -type f -perm -002 -ls 2>/dev/null
sudo chmod o-w /path/to/file  # Remove world-writable permissions


Secure Sensitive Files:

sudo chmod 644 /etc/passwd
sudo chmod 640 /etc/shadow
sudo chown root:root /etc/passwd
sudo chown root:shadow /etc/shadow


Check for SUID/SGID Binaries:

sudo find / -perm -4000 -type f -ls 2>/dev/null
sudo find / -perm -2000 -type f -ls 2>/dev/null

🔟 Additional Security Measures

Configure AppArmor (if necessary):

sudo apt-get install apparmor apparmor-utils -y
sudo systemctl enable apparmor
sudo systemctl start apparmor


Check for Rootkits (use rkhunter):

sudo apt-get install rkhunter -y
sudo rkhunter --update
sudo rkhunter --check --skip

You said:
Oops, forgot to mention that you should format it as a github readme
ChatGPT said:

Got you — here is a fully formatted, cleaned-up, clarified, professionally structured GitHub-style README for your CyberPatriot Linux (Ubuntu 24.04 + Mint 21) Checklist.

Everything is prioritized from most points → least points, unnecessary duplication has been removed, risky items are labeled, and all steps have explanations.

You can paste this directly into a GitHub README.md.

🛡️ CyberPatriot Linux Checklist (Ubuntu 24.04 & Linux Mint 21)

Optimized | Clarified | Prioritized | Competition-Safe

This guide is designed for CyberPatriot Ubuntu 24 & Linux Mint 21 images.
It contains everything needed to earn maximum points in proper priority order, with explanations and safe-to-use commands.

⚠️ CRITICAL: DO THESE FIRST

These steps protect you from losing points or breaking the VM.

1️⃣ Read Everything First

Before touching the machine:

Read the README
Contains required services, allowed software, and authorized users.

Answer all forensics questions
Many forensics rely on an unmodified machine.

Take a VM snapshot
If you break SSH, sudo, bootloader, or a service → you lose points.

🎯 HIGH-PRIORITY TASKS (MOST POINTS)
2️⃣ User Account Management (HUGE POINT VALUE)

Most point losses come from unauthorized users or incorrect permissions.

✔️ List All Users
cat /etc/passwd
awk -F: '$3 >= 1000 {print $1}' /etc/passwd
ls /home/

✔️ Delete Unauthorized Users
sudo userdel -r <username>
sudo userdel <username>       # Keep home directory for forensics

✔️ Remove Unauthorized Admins
getent group sudo
getent group admin

sudo deluser <username> sudo
sudo deluser <username> admin


Check for hidden sudoers rules:

ls -la /etc/sudoers.d/
sudo cat /etc/sudoers.d/*


Remove unknown entries:

sudo rm /etc/sudoers.d/<file>

✔️ Add Missing Users
sudo adduser <username>
sudo usermod -aG sudo <username>   # Only if authorized

✔️ Lock Root Account
sudo passwd -l root

✔️ Disable Guest Login

(Ubuntu with LightDM only)

sudo sh -c 'printf "[Seat:*]\nallow-guest=false\n" > /etc/lightdm/lightdm.conf.d/50-no-guest.conf'

3️⃣ Password Policies (HIGH POINTS)

Strengthens authentication security — always worth lots of points.

✔️ Install password-quality library
sudo apt install libpam-pwquality -y

✔️ Configure strong password requirements

Edit:

sudo nano /etc/pam.d/common-password


Add/modify this line:

password requisite pam_pwquality.so retry=3 minlen=8 difok=3 \
ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1 maxrepeat=2


Explanation:

minlen=8 → Minimum length

ucredit=-1 → Require 1 uppercase

dcredit=-1 → Require 1 digit

etc.

✔️ Configure password aging

Edit:

sudo nano /etc/login.defs


Set:

PASS_MAX_DAYS 90
PASS_MIN_DAYS 10
PASS_WARN_AGE 7
PASS_MIN_LEN 8


Apply to existing users:

for user in $(awk -F: '$3 >= 1000 {print $1}' /etc/passwd); do
  sudo chage -M 90 -m 10 -W 7 "$user"
done

✔️ Force password changes if necessary
sudo passwd -e <username>

4️⃣ System Updates & Patching (HIGH POINTS)
✔️ Update everything
sudo apt update
sudo apt upgrade -y
sudo apt dist-upgrade -y
sudo apt autoremove -y
sudo apt autoclean


Kernel changed? → REBOOT

✔️ Enable automatic security updates
sudo apt install unattended-upgrades -y
sudo dpkg-reconfigure -plow unattended-upgrades

5️⃣ Firewall Configuration (Always Points)

UFW is simple and heavily weighted.

✔️ Install UFW
sudo apt install ufw -y

✔️ Apply default rules
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw enable
sudo ufw status verbose

✔️ Allow only required services
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp

✔️ Enable logging
sudo ufw logging medium

6️⃣ Remove Prohibited Software (Large Points)

Remove anything hacking-related, games, P2P, etc.

✔️ Remove hacking tools
sudo apt purge wireshark nmap john hydra metasploit-framework aircrack-ng \
tcpdump nikto sqlmap netcat -y

✔️ Remove P2P & torrents
sudo apt purge transmission* deluge* frostwire vuze -y

✔️ Remove games
sudo apt purge gnome-games* aisleriot gnome-mahjongg gnome-mines gnome-sudoku -y

✔️ Clean up afterwards
sudo apt autoremove -y
sudo apt autoclean

✔️ Search for prohibited media
sudo find /home -name "*.mp3"
sudo find /home -name "*.mp4"
sudo find /home -name "*.avi"

7️⃣ Service Management (HIGH POINTS)

Disabling insecure/unneeded services earns many points.

✔️ View running services
sudo systemctl list-units --type=service --state=running

✔️ Disable insecure services

(Only if NOT required!)

sudo systemctl disable --now telnet.socket
sudo systemctl disable --now vsftpd
sudo systemctl disable --now apache2
sudo systemctl disable --now nginx
sudo systemctl disable --now mysql
sudo systemctl disable --now postgresql
sudo systemctl disable --now smbd nmbd
sudo systemctl disable --now cups
sudo systemctl disable --now bluetooth
sudo systemctl disable --now avahi-daemon

⚠️ NEVER disable:

ssh / sshd

systemd services

NetworkManager

dbus

Any service required by README

🎯 MEDIUM-PRIORITY TASKS
8️⃣ File Permissions & Security
✔️ Find world-writable files
sudo find / -type f -perm -002 -ls 2>/dev/null
sudo chmod o-w <file>

✔️ Secure /etc critical files
sudo chmod 644 /etc/passwd /etc/group
sudo chmod 640 /etc/shadow /etc/gshadow
sudo chown root:root /etc/passwd
sudo chown root:shadow /etc/shadow

✔️ Check SUID/SGID files
sudo find / -perm -4000 -type f -ls
sudo find / -perm -2000 -type f -ls


⚠️ Only remove SUID if you’re 100% sure.

9️⃣ Network Security
✔️ Disable IPv6 (if not needed)

Edit:

sudo nano /etc/sysctl.conf


Add:

net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1


Apply:

sudo sysctl -p

✔️ Harden sysctl networking

Add to /etc/sysctl.conf:

net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1


Apply:

sudo sysctl -p

🔟 Audit & Logging
✔️ Install auditd
sudo apt install auditd audispd-plugins -y
sudo systemctl enable auditd --now

✔️ Add audit rules

Edit:

sudo nano /etc/audit/rules.d/audit.rules


Add:

-w /etc/passwd -p wa
-w /etc/shadow -p wa
-w /etc/sudoers -p wa
-w /etc/ssh/sshd_config -p wa


Apply:

sudo augenrules --load

🔽 LOWER-PRIORITY TASKS (Still give points)
1️⃣1️⃣ AppArmor
sudo apt install apparmor apparmor-utils -y
sudo systemctl enable apparmor --now
sudo aa-enforce /etc/apparmor.d/*

1️⃣2️⃣ Rootkit Check
sudo apt install rkhunter -y
sudo rkhunter --update
sudo rkhunter --check --skip-keypress

1️⃣3️⃣ Login & Warning Banners
✔️ Pre-login banner
sudo nano /etc/issue.net


Add:

UNAUTHORIZED ACCESS PROHIBITED.
This system is monitored.

1️⃣4️⃣ SSH Hardening (ONLY if SSH required)

Edit:

sudo nano /etc/ssh/sshd_config


Recommended:

PermitRootLogin no
PermitEmptyPasswords no
MaxAuthTries 3
X11Forwarding no


Reload:

sudo systemctl restart sshd
