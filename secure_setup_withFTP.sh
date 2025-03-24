#!/bin/bash

# 🛠️ تنظیمات اولیه
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"
NEW_USER="bigpython"
SSH_PORT="9011"
FTP_PORT="2121"
CODE_SERVER_PORT="1010"
NETDATA_PORT="9001"
CROWDSEC_DASHBOARD_PORT="3000"
PORTAINER_PORT="9000"
CODE_SERVER_PASSWORD="114aa2650b0db5509f36f4fc"
PUBLIC_KEY_URL="https://raw.githubusercontent.com/BigPyth0n/publickey/main/id_rsa.pub"
PORTS_TO_OPEN=("1010" "1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080" "80" "81" "9000" "443" "$SSH_PORT" "$FTP_PORT" "$NETDATA_PORT" "$CROWDSEC_DASHBOARD_PORT" "40000:40100")
LOG_FILE="/var/log/secure_setup.log"

# 🛠️ گرفتن IP سرور (IPv4)
SERVER_IP=$(curl -s -4 icanhazip.com) || { echo "❌ Failed to get server IP"; exit 1; }

# 🛠️ گرفتن محل سرور (تقریبی)
SERVER_LOCATION=$(curl -s "http://ip-api.com/line/$SERVER_IP?fields=country,city" | tr '\n' ', ' | sed 's/, $//') || "Unknown"

# 🛠️ گرفتن نام سرور
SERVER_NAME=$(hostname)

# 🛠️ لیست برنامه‌های نصب‌شده
INSTALLED_APPS="Docker, Docker Compose, Portainer, Code-Server, CrowdSec, Netdata, vsftpd, wget, curl, net-tools, iperf3, htop, glances, tmux, rsync, vim, nano, unzip, zip, build-essential, git, lftp, clamav, clamav-daemon, rkhunter, lynis, auditd, tcpdump, nmap"

# 🛠️ لاگ‌گیری
exec > >(tee -a "$LOG_FILE") 2>&1
echo "📅 Starting setup at $(date)"

# 🛠️ تابع ارسال پیام به تلگرام
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" >/dev/null 2>&1 || echo "⚠️ Failed to send Telegram message"
}

# 🛠️ چک کردن دسترسی root
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root. Exiting."
    exit 1
fi

# 🛠️ 1. اضافه کردن رپوزیتوری‌ها
echo "➕ Adding Ubuntu 20.04 repositories..."
add-apt-repository main -y || { echo "❌ Failed to add main repository"; exit 1; }
add-apt-repository universe -y || { echo "❌ Failed to add universe repository"; exit 1; }
add-apt-repository restricted -y || { echo "❌ Failed to add restricted repository"; exit 1; }
add-apt-repository multiverse -y || { echo "❌ Failed to add multiverse repository"; exit 1; }

# 🛠️ 2. آپدیت و ارتقای سیستم
echo "🔄 Updating and upgrading system..."
apt update && apt upgrade -y || { echo "❌ Failed to update/upgrade system"; exit 1; }

# 🛠️ 3. ایجاد کاربر جدید و تنظیم کلید عمومی از GitHub
echo "👤 Creating secure user: $NEW_USER and setting up SSH key..."
if ! id "$NEW_USER" &>/dev/null; then
    adduser --disabled-password --gecos "" "$NEW_USER" || { echo "❌ Failed to create user $NEW_USER"; exit 1; }
    usermod -aG sudo "$NEW_USER" || { echo "❌ Failed to add $NEW_USER to sudo group"; exit 1; }
    echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER" || { echo "❌ Failed to set sudoers for $NEW_USER"; exit 1; }
    chmod 440 /etc/sudoers.d/"$NEW_USER"
fi

if [[ ! -d "/home/$NEW_USER" ]]; then
    echo "❌ Home directory /home/$NEW_USER does not exist. Creating it..."
    mkdir -p "/home/$NEW_USER" || { echo "❌ Failed to create /home/$NEW_USER"; exit 1; }
    chown "$NEW_USER":"$NEW_USER" "/home/$NEW_USER"
fi

mkdir -p "/home/$NEW_USER/.ssh" || { echo "❌ Failed to create .ssh directory"; exit 1; }
curl -s -o "/home/$NEW_USER/.ssh/authorized_keys" "$PUBLIC_KEY_URL" || { echo "❌ Failed to download public key"; exit 1; }
if [[ ! -s "/home/$NEW_USER/.ssh/authorized_keys" ]]; then
    echo "❌ Public key file is empty or not downloaded correctly"
    exit 1
fi
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.ssh" || { echo "❌ Failed to set ownership for .ssh"; exit 1; }
chmod 700 "/home/$NEW_USER/.ssh" || { echo "❌ Failed to set permissions for .ssh"; exit 1; }
chmod 600 "/home/$NEW_USER/.ssh/authorized_keys" || { echo "❌ Failed to set permissions for authorized_keys"; exit 1; }

# 🛠️ 4. نصب ملزومات (Docker و ابزارهای پایه)
echo "🐳 Installing Docker and prerequisites..."
apt install -y apt-transport-https ca-certificates curl software-properties-common || { echo "❌ Failed to install prerequisites"; exit 1; }
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - || { echo "❌ Failed to add Docker GPG key"; exit 1; }
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable" || { echo "❌ Failed to add Docker repository"; exit 1; }
apt update || { echo "❌ Failed to update apt after adding Docker repo"; exit 1; }
apt install -y docker-ce || { echo "❌ Failed to install Docker"; exit 1; }
systemctl enable --now docker || { echo "❌ Failed to enable/start Docker"; exit 1; }
usermod -aG docker "$NEW_USER" || { echo "❌ Failed to add $NEW_USER to docker group"; exit 1; }

echo "🐳 Installing Docker Compose..."
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose || { echo "❌ Failed to download Docker Compose"; exit 1; }
chmod +x /usr/local/bin/docker-compose || { echo "❌ Failed to make Docker Compose executable"; exit 1; }
docker-compose --version || { echo "❌ Docker Compose installation failed"; exit 1; }

echo "🐳 Installing Portainer..."
docker volume create portainer_data || { echo "❌ Failed to create Portainer volume"; exit 1; }
docker run -d \
    --name portainer \
    -p $PORTAINER_PORT:9000 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    --restart unless-stopped \
    portainer/portainer-ce:latest || { echo "❌ Failed to run Portainer"; exit 1; }
echo "⚠️ Portainer installed! Set the initial password at http://$SERVER_IP:$PORTAINER_PORT after the script finishes."

# 🛠️ 5. نصب نسخه‌های مختلف پایتون
echo "🐍 Installing Python versions..."
apt install -y software-properties-common build-essential libssl-dev zlib1g-dev \
libbz2-dev libreadline-dev libsqlite3-dev wget curl llvm libncurses5-dev \
libncursesw5-dev xz-utils tk-dev libffi-dev liblzma-dev python3-openssl || { echo "❌ Failed to install Python prerequisites"; exit 1; }

add-apt-repository ppa:deadsnakes/ppa -y || { echo "❌ Failed to add deadsnakes PPA"; exit 1; }
apt update || { echo "❌ Failed to update apt after adding PPA"; exit 1; }

echo "🔹 Installing Python 3.8 (system default) with apt_pkg..."
apt install -y python3.8 python3.8-dev python3.8-venv python3.8-distutils python3-apt || { echo "❌ Failed to install Python 3.8"; exit 1; }

echo "🔹 Installing Python 3.10..."
apt install -y python3.10 python3.10-dev python3.10-venv python3.10-distutils || { echo "❌ Failed to install Python 3.10"; exit 1; }

update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.8 8
update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 10
update-alternatives --set python3 /usr/bin/python3.10 || { echo "❌ Failed to set Python 3.10 as default"; exit 1; }

wget -O get-pip.py https://bootstrap.pypa.io/get-pip.py || { echo "❌ Failed to download get-pip.py"; exit 1; }
python3.8 get-pip.py || { echo "❌ Failed to install pip for Python 3.8"; exit 1; }
python3.10 get-pip.py || { echo "❌ Failed to install pip for Python 3.10"; exit 1; }
rm -f get-pip.py
python3.8 -m pip install --upgrade pip || { echo "❌ Failed to upgrade pip for Python 3.8"; exit 1; }
python3.10 -m pip install --upgrade pip || { echo "❌ Failed to upgrade pip for Python 3.10"; exit 1; }

ln -sf /usr/local/bin/pip3.10 /usr/local/bin/pip || { echo "❌ Failed to link pip"; exit 1; }
ln -sf /usr/local/bin/pip3.10 /usr/local/bin/pip3 || { echo "❌ Failed to link pip3"; exit 1; }

echo "🔍 Testing default Python version (should be 3.10)..."
python3 -c "import sys; print(f'Default Python: {sys.version}')" || { echo "❌ Python 3.10 not working"; exit 1; }
echo "⚠️ Note: Use /usr/bin/python3.8 for tasks requiring apt_pkg."

# 🛠️ 6. تنظیم پورت SSH و امنیت
echo "🔒 Configuring SSH..."
sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/^Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
systemctl restart sshd || { echo "❌ Failed to restart SSH"; exit 1; }

# 🛠️ 7. نصب Nginx Proxy Manager
echo "🌐 Installing Nginx Proxy Manager via Docker..."
mkdir -p /opt/nginx-proxy-manager/data /opt/nginx-proxy-manager/letsencrypt || { echo "❌ Failed to create Nginx Proxy Manager directories"; exit 1; }
docker run -d \
    --name nginx-proxy-manager \
    -p 80:80 -p 81:81 -p 443:443 \
    -v /opt/nginx-proxy-manager/data:/data \
    -v /opt/nginx-proxy-manager/letsencrypt:/etc/letsencrypt \
    --restart unless-stopped \
    jc21/nginx-proxy-manager:latest || { echo "❌ Failed to run Nginx Proxy Manager"; exit 1; }

# 🛠️ 8. نصب Code-Server
echo "💻 Installing Code-Server..."
curl -fsSL https://code-server.dev/install.sh | sh || { echo "❌ Failed to install Code-Server"; exit 1; }
systemctl enable --now code-server@"$NEW_USER" || { echo "❌ Failed to enable Code-Server"; exit 1; }
mkdir -p "/home/$NEW_USER/.config/code-server" || { echo "❌ Failed to create Code-Server config dir"; exit 1; }
cat <<EOL > "/home/$NEW_USER/.config/code-server/config.yaml"
bind-addr: 0.0.0.0:$CODE_SERVER_PORT
auth: password
password: $CODE_SERVER_PASSWORD
cert: false
EOL
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.config" || { echo "❌ Failed to set ownership for Code-Server config"; exit 1; }
setcap 'cap_net_bind_service=+ep' /usr/lib/code-server/lib/node || { echo "❌ Failed to set capabilities for Code-Server"; exit 1; }
systemctl restart code-server@"$NEW_USER" || { echo "❌ Failed to restart Code-Server"; exit 1; }

# 🛠️ 9. تنظیم فایروال UFW
echo "🔥 Configuring UFW..."
ufw default deny incoming || { echo "❌ Failed to set UFW default deny"; exit 1; }
ufw default allow outgoing || { echo "❌ Failed to set UFW default allow"; exit 1; }
for port in "${PORTS_TO_OPEN[@]}"; do
    ufw allow "$port/tcp" || { echo "❌ Failed to allow port $port"; exit 1; }
done
ufw --force enable || { echo "❌ Failed to enable UFW"; exit 1; }

# 🛠️ 10. نصب و تنظیم CrowdSec
echo "🛡️ Installing CrowdSec core..."
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash || { echo "❌ Failed to add CrowdSec repo"; exit 1; }
apt install -y crowdsec || { echo "❌ Failed to install CrowdSec"; exit 1; }
cat <<EOL > /etc/crowdsec/acquis.yaml
---
filenames:
  - /var/log/nginx/access.log
  - /var/log/nginx/error.log
  - /var/log/vsftpd.log
  - /var/log/auth.log
labels:
  type: nginx
---
filenames:
  - /var/log/auth.log
labels:
  type: syslog
---
filenames:
  - /var/log/vsftpd.log
labels:
  type: vsftpd
EOL
sed -i "s/ssh_port: '22'/ssh_port: '$SSH_PORT'/" /etc/crowdsec/parsers/s01-parse/sshd-logs.yaml
systemctl enable crowdsec || { echo "❌ Failed to enable CrowdSec"; exit 1; }
systemctl start crowdsec || { echo "❌ Failed to start CrowdSec"; exit 1; }

echo "🛡️ Installing CrowdSec firewall bouncer..."
apt install -y crowdsec-firewall-bouncer-iptables || { echo "❌ Failed to install CrowdSec bouncer"; exit 1; }
cscli machines add --auto --force || { echo "❌ Failed to add CrowdSec machine"; exit 1; }
systemctl enable crowdsec-firewall-bouncer || { echo "❌ Failed to enable CrowdSec bouncer"; exit 1; }
systemctl start crowdsec-firewall-bouncer || { echo "❌ Failed to start CrowdSec bouncer"; exit 1; }

echo "🛡️ Setting up CrowdSec dashboard..."
cscli dashboard setup --listen 0.0.0.0 || { echo "❌ Failed to setup CrowdSec dashboard"; exit 1; }
sleep 30
CROWDSEC_PASSWORD=$(grep "password" /etc/crowdsec/metabase/metabase.yaml | awk '{print $2}' | tr -d '"')

echo "🛡️ Setting up Telegram notification for CrowdSec..."
apt install -y crowdsec-custom-bouncer || { echo "❌ Failed to install CrowdSec custom bouncer"; exit 1; }
cat <<EOL > /etc/crowdsec/notifications/http.yaml
type: http
name: http_telegram
url: "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage"
method: POST
headers:
  Content-Type: "application/x-www-form-urlencoded"
body: "chat_id=$TELEGRAM_CHAT_ID&text=🚨 حمله تشخیص داده شد!\nسرور: $(hostname)\nنوع حمله: \${scenario}\nIP مهاجم: \${source_ip}\nزمان: \${time}\nجزئیات: \${alert}"
EOL
cscli notifications add /etc/crowdsec/notifications/http.yaml || { echo "❌ Failed to add CrowdSec notification"; exit 1; }
sed -i '/^notifications:/a\  - http_telegram' /etc/crowdsec/config.yaml
systemctl restart crowdsec || { echo "❌ Failed to restart CrowdSec"; exit 1; }

# 🛠️ 11. نصب ابزارهای اضافی و Netdata
echo "📦 Installing additional tools and Netdata..."
apt install -y wget curl net-tools iperf3 htop glances tmux rsync vim nano unzip zip build-essential git lftp \
               clamav clamav-daemon rkhunter lynis auditd tcpdump nmap netdata || { echo "❌ Failed to install tools"; exit 1; }
cat <<EOL > /etc/netdata/netdata.conf
[global]
    run as user = netdata
    web files owner = root
    web files group = root
[web]
    bind to = 0.0.0.0:$NETDATA_PORT
EOL
systemctl enable netdata || { echo "❌ Failed to enable Netdata"; exit 1; }
systemctl restart netdata || { echo "❌ Failed to restart Netdata"; exit 1; }
systemctl stop postfix && systemctl disable postfix

# 🛠️ 12. تنظیمات امنیتی سیستمی
echo "🔧 Applying system security settings..."
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv4.conf.default.secure_redirects=0
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w kernel.yama.ptrace_scope=1
sysctl -p || { echo "❌ Failed to apply sysctl settings"; exit 1; }

# 🛠️ 13. تنظیم اسکن‌های روزانه
echo "⏰ Setting up daily scans..."
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/bin/clamscan -r / --exclude-dir=/sys/ --exclude-dir=/proc/ --exclude-dir=/dev/ -l /var/log/clamav/scan.log") | crontab -
(crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/rkhunter --check --sk") | crontab -
(crontab -l 2>/dev/null; echo "0 4 * * * /usr/bin/lynis audit system") | crontab -

# 🛠️ 14. راه‌اندازی مجدد سرویس‌ها
echo "🔄 Reloading services..."
systemctl restart sshd || { echo "❌ Failed to restart SSH"; exit 1; }
ufw reload || { echo "❌ Failed to reload UFW"; exit 1; }

# 🛠️ 15. نصب و تنظیم FTP
echo "📡 Setting up FTP server (vsftpd) with user 'secftpuser' without SSL..."
apt install -y vsftpd || { echo "❌ Failed to install vsftpd"; exit 1; }
systemctl stop vsftpd

if ! id "secftpuser" &>/dev/null; then
    echo "👤 Creating FTP user: secftpuser..."
    useradd -m -d /home/secftpuser -s /bin/bash secftpuser || { echo "❌ Failed to create secftpuser"; exit 1; }
    echo "secftpuser:YumJdc\$Qvs3mZ^*dFJxa" | chpasswd || { echo "❌ Failed to set password for secftpuser"; exit 1; }
fi

chown secftpuser:secftpuser "/home/$NEW_USER" || { echo "❌ Failed to set ownership for /home/$NEW_USER"; exit 1; }
chmod 750 "/home/$NEW_USER" || { echo "❌ Failed to set permissions for /home/$NEW_USER"; exit 1; }

cat <<EOL > /etc/vsftpd.conf
listen=YES
listen_port=2121
anonymous_enable=NO
local_enable=YES
write_enable=YES
local_umask=022
chroot_local_user=YES
chroot_list_enable=YES
chroot_list_file=/etc/vsftpd.chroot_list
allow_writeable_chroot=YES
userlist_enable=YES
userlist_file=/etc/vsftpd.userlist
userlist_deny=NO
ssl_enable=NO
pasv_enable=YES
pasv_min_port=40000
pasv_max_port=40100
pasv_address=$SERVER_IP
xferlog_enable=YES
xferlog_file=/var/log/vsftpd.log
EOL

echo "secftpuser" > /etc/vsftpd.userlist
echo "secftpuser" > /etc/vsftpd.chroot_list
usermod -d "/home/$NEW_USER" secftpuser || { echo "❌ Failed to set home dir for secftpuser"; exit 1; }

chmod 600 /etc/vsftpd.conf /etc/vsftpd.userlist /etc/vsftpd.chroot_list || { echo "❌ Failed to set permissions for vsftpd configs"; exit 1; }
chown root:root /etc/vsftpd.conf /etc/vsftpd.userlist /etc/vsftpd.chroot_list || { echo "❌ Failed to set ownership for vsftpd configs"; exit 1; }

systemctl enable vsftpd || { echo "❌ Failed to enable vsftpd"; exit 1; }
systemctl start vsftpd || { echo "❌ Failed to start vsftpd"; exit 1; }

# 🛠️ 16. تست نهایی SSH و Docker
echo "🔍 Final check for SSH and Docker..."
if systemctl is-active sshd >/dev/null && systemctl is-active docker >/dev/null; then
    echo "✅ SSH and Docker are running successfully!"
    REPORT=$(cat <<EOL
📌 گزارش نصب سرور
{
  "نام سرور": "$SERVER_NAME",
  "IP سرور": "$SERVER_IP",
  "محل سرور": "$SERVER_LOCATION",
  "پورت SSH": "$SSH_PORT",
  "برنامه‌های نصب‌شده": [
    "Docker", "Docker Compose", "Portainer", "Code-Server", "CrowdSec", "Netdata", "vsftpd",
    "wget, curl, net-tools, iperf3", "htop, glances, tmux", "rsync, vim, nano, unzip, zip",
    "build-essential, git, lftp", "clamav, clamav-daemon, rkhunter, lynis", "auditd, tcpdump, nmap"
  ],
  "سرویس‌های قابل دسترسی": [
    {"نام": "FTP (vsftpd)", "آدرس": "ftp://$SERVER_IP:2121", "نام کاربری": "secftpuser", "رمز": "YumJdc\$Qvs3mZ^*dFJxa", "توضیحات": "دسترسی به /home/bigpython"},
    {"نام": "Code-Server", "آدرس": "http://$SERVER_IP:$CODE_SERVER_PORT", "نام کاربری": "N/A", "رمز": "$CODE_SERVER_PASSWORD"},
    {"نام": "CrowdSec Dashboard", "آدرس": "http://$SERVER_IP:$CROWDSEC_DASHBOARD_PORT", "نام کاربری": "crowdsec@crowdsec.net", "رمز": "$CROWDSEC_PASSWORD"},
    {"نام": "Netdata", "آدرس": "http://$SERVER_IP:$NETDATA_PORT", "نام کاربری": "N/A", "رمز": "N/A"},
    {"نام": "Nginx Proxy Manager", "آدرس": "http://$SERVER_IP:81", "نام کاربری": "پیش‌فرض", "رمز": "پیش‌فرض (بعد از ورود تغییر دهید)"},
    {"نام": "Portainer", "آدرس": "http://$SERVER_IP:$PORTAINER_PORT", "نام کاربری": "N/A (اولین ورود رمز تنظیم کنید)", "رمز": "N/A (اولین ورود رمز تنظیم کنید)"}
  ],
  "زمان نصب": "$(date)"
}
➖ نصب با موفقیت انجام شد!
EOL
    )
    send_telegram "$REPORT"
else
    echo "❌ Problem detected: SSH or Docker is not running."
    send_telegram "❌ مشکلی در سرور وجود دارد: SSH یا Docker فعال نیست - $(hostname) در $(date)"
    exit 1
fi

echo "🔄 Restarting Portainer to reset timeout..."
docker restart portainer || { echo "❌ Failed to restart Portainer"; exit 1; }
echo "✅ Portainer restarted! Access http://$SERVER_IP:$PORTAINER_PORT within 5 minutes to set the initial password."

echo "✅ Secure setup completed successfully at $(date)!"
exit 0
