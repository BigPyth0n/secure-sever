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
SERVER_IP=$(curl -s -4 icanhazip.com)

# 🛠️ گرفتن محل سرور (تقریبی)
SERVER_LOCATION=$(curl -s "http://ip-api.com/line/$SERVER_IP?fields=country,city" | tr '\n' ', ' | sed 's/, $//')

# 🛠️ گرفتن نام سرور
SERVER_NAME=$(hostname)

# 🛠️ لیست برنامه‌های نصب‌شده
INSTALLED_APPS="Docker, Docker Compose, Portainer, Code-Server, CrowdSec, Netdata, vsftpd, TA-Lib, wget, curl, net-tools, iperf3, htop, glances, tmux, rsync, vim, nano, unzip, zip, build-essential, git, lftp, clamav, clamav-daemon, rkhunter, lynis, auditd, tcpdump, nmap"

# 🛠️ لاگ‌گیری
exec > >(tee -a "$LOG_FILE") 2>&1
echo "📅 Starting setup at $(date)"

# 🛠️ تابع ارسال پیام به تلگرام
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" >/dev/null 2>&1
}

# 🛠️ چک کردن دسترسی root
if [[ $EUID -ne 0 ]]; then
    echo "❌ This script must be run as root. Exiting."
    exit 1
fi

# 🛠️ 1. اضافه کردن رپوزیتوری‌ها
echo "➕ Adding Ubuntu 20.04 repositories..."
add-apt-repository main -y || { echo "Failed to add main repository"; exit 1; }
add-apt-repository universe -y || { echo "Failed to add universe repository"; exit 1; }
add-apt-repository restricted -y || { echo "Failed to add restricted repository"; exit 1; }
add-apt-repository multiverse -y || { echo "Failed to add multiverse repository"; exit 1; }

# 🛠️ 2. آپدیت و ارتقای سیستم
echo "🔄 Updating and upgrading system..."
apt update && apt upgrade -y || { echo "Failed to update/upgrade system"; exit 1; }

# 🛠️ 3. ایجاد کاربر جدید و تنظیم کلید عمومی از GitHub
echo "👤 Creating secure user: $NEW_USER and setting up SSH key..."
if ! id "$NEW_USER" &>/dev/null; then
    adduser --disabled-password --gecos "" "$NEW_USER"
    usermod -aG sudo "$NEW_USER"
    echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER"
    chmod 440 /etc/sudoers.d/"$NEW_USER"
fi
mkdir -p /home/"$NEW_USER"/.ssh
curl -s "$PUBLIC_KEY_URL" > /home/"$NEW_USER"/.ssh/authorized_keys
chown -R "$NEW_USER":"$NEW_USER" /home/"$NEW_USER"/.ssh
chmod 700 /home/"$NEW_USER"/.ssh
chmod 600 /home/"$NEW_USER"/.ssh/authorized_keys

# چک کردن کلید عمومی
if [[ -s /home/"$NEW_USER"/.ssh/authorized_keys && $(stat -c %a /home/"$NEW_USER"/.ssh/authorized_keys) -eq 600 ]]; then
    echo "✅ SSH public key successfully downloaded and permissions set."
else
    echo "❌ Failed to download or set permissions for SSH public key."
    exit 1
fi

# 🛠️ 4. نصب ملزومات (Docker و ابزارهای پایه)
echo "🐳 Installing Docker and prerequisites..."
apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
apt update
apt install -y docker-ce
systemctl enable --now docker || { echo "Failed to enable/start Docker"; exit 1; }
usermod -aG docker "$NEW_USER" || { echo "Failed to add $NEW_USER to docker group"; exit 1; }

# نصب Docker Compose
echo "🐳 Installing Docker Compose..."
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
docker-compose --version || { echo "Failed to install Docker Compose"; exit 1; }

# نصب Portainer
echo "🐳 Installing Portainer..."
docker volume create portainer_data
docker run -d \
    --name portainer \
    -p $PORTAINER_PORT:9000 \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    --restart unless-stopped \
    portainer/portainer-ce:latest || { echo "Failed to run Portainer"; exit 1; }
echo "⚠️ Portainer installed! You will need to set the initial password at http://$SERVER_IP:$PORTAINER_PORT after the script finishes."


# 🛠️ 5. نصب پایتون‌های مختلف و تنظیم پیش‌فرض
echo "🐍 Installing Python 3.10 and 3.11 with full dependencies..."
add-apt-repository ppa:deadsnakes/ppa -y
apt update
# نصب پایتون 3.10 با تمام وابستگی‌ها (بدون python3-pip)
apt install -y python3.10 \
               python3.10-dev \
               python3.10-distutils \
               python3.10-venv \
               python3.10-lib2to3 \
               python3.10-gdbm \
               python3.10-tk \
               python3-apt || { echo "Failed to install Python 3.10 with dependencies"; exit 1; }
# نصب پایتون 3.11 با تمام وابستگی‌ها (بدون python3-pip)
apt install -y python3.11 \
               python3.11-dev \
               python3.11-distutils \
               python3.11-venv \
               python3.11-lib2to3 \
               python3.11-gdbm \
               python3.11-tk || { echo "Failed to install Python 3.11 with dependencies"; exit 1; }

# تنظیم update-alternatives برای نسخه‌ها
update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.10 10
update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 11

# تنظیم پایتون 3.10 به‌عنوان پیش‌فرض
update-alternatives --set python3 /usr/bin/python3.10 || { echo "Failed to set Python 3.10 as default"; exit 1; }

# نصب و به‌روزرسانی pip با get-pip.py
echo "🔄 Installing and updating pip for all Python versions..."
wget -O get-pip.py https://bootstrap.pypa.io/get-pip.py || { echo "Failed to download get-pip.py"; exit 1; }
/usr/bin/python3.10 get-pip.py || { echo "Failed to install pip for Python 3.10"; exit 1; }
/usr/bin/python3.11 get-pip.py || { echo "Failed to install pip for Python 3.11"; exit 1; }
/usr/bin/python3.10 -m pip install --upgrade pip || { echo "Failed to upgrade pip for Python 3.10"; exit 1; }
/usr/bin/python3.11 -m pip install --upgrade pip || { echo "Failed to upgrade pip for Python 3.11"; exit 1; }
rm -f get-pip.py

# تست نسخه پیش‌فرض (3.10)
echo "🔍 Testing default Python version (should be 3.10)..."
python3 -c "import sys; print(f'Python version: {sys.version}')" || { echo "❌ Default Python not working"; exit 1; }

# تست دسترسی به apt_pkg برای سازگاری سیستمی
echo "🔍 Ensuring apt_pkg is available for Python 3.10..."
python3 -c "import apt_pkg" || { echo "⚠️ apt_pkg not found for Python 3.10, attempting to fix..."; apt install --reinstall python3-apt -y; python3 -c "import apt_pkg" || { echo "❌ Failed to fix apt_pkg"; exit 1; }; }



# 🛠️ 6. تنظیم پورت SSH و امنیت
echo "🔒 Configuring SSH..."
sed -i "s/^#Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i "s/^Port 22/Port $SSH_PORT/" /etc/ssh/sshd_config
sed -i 's/^#PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^PasswordAuthentication yes/PasswordAuthentication no/' /etc/ssh/sshd_config
sed -i 's/^#PubkeyAuthentication yes/PubkeyAuthentication yes/' /etc/ssh/sshd_config
sed -i 's/^PubkeyAuthentication no/PubkeyAuthentication yes/' /etc/ssh/sshd_config
echo "PermitRootLogin no" >> /etc/ssh/sshd_config
systemctl restart sshd || { echo "Failed to restart SSH"; exit 1; }

# 🛠️ 7. نصب Nginx Proxy Manager به صورت داکر با تنظیمات لوکال
echo "🌐 Installing Nginx Proxy Manager via Docker..."
mkdir -p /opt/nginx-proxy-manager/data /opt/nginx-proxy-manager/letsencrypt
docker run -d \
    --name nginx-proxy-manager \
    -p 80:80 -p 81:81 -p 443:443 \
    -v /opt/nginx-proxy-manager/data:/data \
    -v /opt/nginx-proxy-manager/letsencrypt:/etc/letsencrypt \
    --restart unless-stopped \
    jc21/nginx-proxy-manager:latest || { echo "Failed to run Nginx Proxy Manager"; exit 1; }

# 🛠️ 8. نصب Code-Server
echo "💻 Installing Code-Server..."
curl -fsSL https://code-server.dev/install.sh | sh
sudo systemctl enable --now code-server@"$NEW_USER"
mkdir -p /home/"$NEW_USER"/.config/code-server
cat <<EOL > /home/"$NEW_USER"/.config/code-server/config.yaml
bind-addr: 0.0.0.0:$CODE_SERVER_PORT
auth: password
password: $CODE_SERVER_PASSWORD
cert: false
EOL
chown -R "$NEW_USER":"$NEW_USER" /home/"$NEW_USER"/.config
sudo setcap 'cap_net_bind_service=+ep' /usr/lib/code-server/lib/node || { echo "Failed to set capabilities for Code-Server"; exit 1; }
sudo systemctl restart code-server@"$NEW_USER" || { echo "Failed to restart Code-Server"; exit 1; }

# 🛠️ 9. تنظیم فایروال UFW
echo "🔥 Configuring UFW..."
ufw default deny incoming
ufw default allow outgoing
for port in "${PORTS_TO_OPEN[@]}"; do
    ufw allow "$port"/tcp
done
ufw --force enable || { echo "Failed to enable UFW"; exit 1; }

# 🛠️ 10. نصب و تنظیم CrowdSec با داشبورد و اعلان تلگرام
echo "🛡️ Installing CrowdSec core..."
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt install -y crowdsec
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
systemctl enable crowdsec
systemctl start crowdsec || { echo "Failed to start CrowdSec core"; exit 1; }

echo "🛡️ Installing CrowdSec firewall bouncer..."
apt install -y crowdsec-firewall-bouncer-iptables
cscli machines add --auto
systemctl enable crowdsec-firewall-bouncer
systemctl start crowdsec-firewall-bouncer || { echo "Failed to start CrowdSec bouncer"; exit 1; }

echo "🛡️ Setting up CrowdSec dashboard (interactive)..."
cscli dashboard setup --listen 0.0.0.0
sleep 30
CROWDSEC_PASSWORD=$(grep "password" /etc/crowdsec/metabase/metabase.yaml | awk '{print $2}' | tr -d '"')

echo "🛡️ Setting up Telegram notification for CrowdSec..."
apt install -y crowdsec-custom-bouncer
cat <<EOL > /etc/crowdsec/notifications/http.yaml
type: http
name: http_telegram
url: "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage"
method: POST
headers:
  Content-Type: "application/x-www-form-urlencoded"
body: "chat_id=$TELEGRAM_CHAT_ID&text=🚨 حمله تشخیص داده شد!\nسرور: $(hostname)\nنوع حمله: \${scenario}\nIP مهاجم: \${source_ip}\nزمان: \${time}\nجزئیات: \${alert}"
EOL
cscli notifications add /etc/crowdsec/notifications/http.yaml
sed -i '/^notifications:/a\  - http_telegram' /etc/crowdsec/config.yaml
systemctl restart crowdsec || { echo "Failed to restart CrowdSec"; exit 1; }

# 🛠️ 11. نصب ابزارهای اضافی و Netdata
echo "📦 Installing additional tools and Netdata..."
apt install -y wget curl net-tools iperf3 htop glances tmux rsync vim nano unzip zip build-essential git lftp \
               clamav clamav-daemon rkhunter lynis auditd tcpdump nmap || { echo "Failed to install additional tools"; exit 1; }
apt install -y netdata || { echo "Failed to install Netdata package"; exit 1; }
cat <<EOL > /etc/netdata/netdata.conf
[global]
    run as user = netdata
    web files owner = root
    web files group = root
[web]
    bind to = 0.0.0.0:$NETDATA_PORT
EOL
systemctl enable netdata
systemctl restart netdata || { echo "Failed to restart Netdata"; exit 1; }
systemctl stop postfix
systemctl disable postfix

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
sysctl -p

# 🛠️ 13. تنظیم اسکن‌های روزانه
echo "⏰ Setting up daily scans..."
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/bin/clamscan -r / --exclude-dir=/sys/ --exclude-dir=/proc/ --exclude-dir=/dev/ -l /var/log/clamav/scan.log") | crontab -
(crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/rkhunter --check --sk") | crontab -
(crontab -l 2>/dev/null; echo "0 4 * * * /usr/bin/lynis audit system") | crontab -

# 🛠️ 14. راه‌اندازی مجدد سرویس‌ها
echo "🔄 Reloading services..."
systemctl restart sshd
ufw reload

# 🛠️ 15. نصب و تنظیم FTP با کاربر secftpuser (بدون SSL)
echo "📡 Setting up FTP server (vsftpd) with user 'secftpuser' without SSL..."
apt install -y vsftpd || { echo "Failed to install vsftpd"; exit 1; }
systemctl stop vsftpd

# چک کردن و ایجاد کاربر secftpuser
if ! id "secftpuser" &>/dev/null; then
    echo "👤 Creating FTP user: secftpuser..."
    useradd -m -d /home/secftpuser -s /bin/bash secftpuser
    echo "secftpuser:YumJdc\$Qvs3mZ^*dFJxa" | chpasswd
fi
if ! id "$NEW_USER" &>/dev/null; then
    echo "❌ User $NEW_USER not found! This should not happen."
    exit 1
fi

# تنظیم دسترسی به /home/bigpython
chown secftpuser:secftpuser /home/bigpython
chmod 750 /home/bigpython

# تنظیمات vsftpd بدون SSL
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
usermod -d /home/bigpython secftpuser

chmod 600 /etc/vsftpd.conf /etc/vsftpd.userlist /etc/vsftpd.chroot_list
chown root:root /etc/vsftpd.conf /etc/vsftpd.userlist /etc/vsftpd.chroot_list

systemctl enable vsftpd
systemctl start vsftpd || { echo "Failed to start vsftpd"; exit 1; }

# 🛠️ 16. نصب TA-Lib از سورس با تمام وابستگی‌ها
echo "📈 Installing TA-Lib from source with full dependencies..."
# نصب پیش‌نیازها
apt install -y build-essential libncurses5-dev libncursesw5-dev wget || { echo "Failed to install TA-Lib prerequisites"; exit 1; }
# دانلود و استخراج TA-Lib
wget -O ta-lib-0.4.0-src.tar.gz http://prdownloads.sourceforge.net/ta-lib/ta-lib-0.4.0-src.tar.gz || { echo "Failed to download TA-Lib"; exit 1; }
tar zxvf ta-lib-0.4.0-src.tar.gz || { echo "Failed to extract TA-Lib"; exit 1; }
cd ta-lib
# تنظیم و کامپایل
./configure --prefix=/usr || { echo "Failed to configure TA-Lib"; exit 1; }
make || { echo "Failed to compile TA-Lib"; exit 1; }
make install || { echo "Failed to install TA-Lib"; exit 1; }
# برگشت به دایرکتوری اصلی
cd ..
# نصب نسخه پایتون TA-Lib برای پایتون پیش‌فرض (3.10)
/usr/bin/python3.10 -m pip install TA-Lib || { echo "Failed to install TA-Lib Python package for 3.10"; exit 1; }
# نصب اختیاری برای نسخه 3.11
/usr/bin/python3.11 -m pip install TA-Lib || echo "Warning: Failed to install TA-Lib for 3.11, continuing..."
# تست نصب TA-Lib
echo "🔍 Testing TA-Lib installation for Python 3.10..."
TALIB_VERSION=$(python3 -c "import talib; print(talib.__version__)" 2>/dev/null) || { echo "❌ TA-Lib not working with Python 3.10"; exit 1; }
echo "✅ TA-Lib version $TALIB_VERSION installed successfully!"
# ارسال گزارش نصب TA-Lib به تلگرام
TALIB_REPORT="📈 نصب TA-Lib\nسرور: $SERVER_NAME\nنسخه: $TALIB_VERSION\nپایتون پیش‌فرض: 3.10\nزمان: $(date)"
send_telegram "$TALIB_REPORT"
# پاکسازی
rm -rf ta-lib ta-lib-0.4.0-src.tar.gz

# 🛠️ 17. تست نهایی SSH و Docker
echo "🔍 Final check for SSH and Docker..."
if systemctl is-active sshd >/dev/null && systemctl is-active docker >/dev/null; then
    echo "✅ SSH and Docker are running successfully!"
    REPORT=$(echo -e "📌 گزارش نصب سرور"
    echo -e "{"
    echo -e "  \"نام سرور\": \"$SERVER_NAME\","
    echo -e "  \"IP سرور\": \"$SERVER_IP\","
    echo -e "  \"محل سرور\": \"$SERVER_LOCATION\","
    echo -e "  \"پورت SSH\": \"$SSH_PORT\","
    echo -e "  \"برنامه‌های نصب‌شده\": ["
    echo -e "    \"Docker\","
    echo -e "    \"Docker Compose\","
    echo -e "    \"Portainer\","
    echo -e "    \"Code-Server\","
    echo -e "    \"CrowdSec\","
    echo -e "    \"Netdata\","
    echo -e "    \"vsftpd\","
    echo -e "    \"TA-Lib\","
    echo -e "    \"wget, curl, net-tools, iperf3\","
    echo -e "    \"htop, glances, tmux\","
    echo -e "    \"rsync, vim, nano, unzip, zip\","
    echo -e "    \"build-essential, git, lftp\","
    echo -e "    \"clamav, clamav-daemon, rkhunter, lynis\","
    echo -e "    \"auditd, tcpdump, nmap\""
    echo -e "  ],"
    echo -e "  \"سرویس‌های قابل دسترسی\": ["
    echo -e "    {"
    echo -e "      \"نام\": \"FTP (vsftpd)\","
    echo -e "      \"آدرس\": \"ftp://$SERVER_IP:2121\","
    echo -e "      \"نام کاربری\": \"secftpuser\","
    echo -e "      \"رمز\": \"YumJdc\$Qvs3mZ^*dFJxa\","
    echo -e "      \"توضیحات\": \"دسترسی به /home/bigpython\""
    echo -e "    },"
    echo -e "    {"
    echo -e "      \"نام\": \"Code-Server\","
    echo -e "      \"آدرس\": \"http://$SERVER_IP:$CODE_SERVER_PORT\","
    echo -e "      \"نام کاربری\": \"N/A\","
    echo -e "      \"رمز\": \"$CODE_SERVER_PASSWORD\""
    echo -e "    },"
    echo -e "    {"
    echo -e "      \"نام\": \"CrowdSec Dashboard\","
    echo -e "      \"آدرس\": \"http://$SERVER_IP:$CROWDSEC_DASHBOARD_PORT\","
    echo -e "      \"نام کاربری\": \"crowdsec@crowdsec.net\","
    echo -e "      \"رمز\": \"$CROWDSEC_PASSWORD\""
    echo -e "    },"
    echo -e "    {"
    echo -e "      \"نام\": \"Netdata\","
    echo -e "      \"آدرس\": \"http://$SERVER_IP:$NETDATA_PORT\","
    echo -e "      \"نام کاربری\": \"N/A\","
    echo -e "      \"رمز\": \"N/A\""
    echo -e "    },"
    echo -e "    {"
    echo -e "      \"نام\": \"Nginx Proxy Manager\","
    echo -e "      \"آدرس\": \"http://$SERVER_IP:81\","
    echo -e "      \"نام کاربری\": \"پیش‌فرض\","
    echo -e "      \"رمز\": \"پیش‌فرض (بعد از ورود تغییر دهید)\""
    echo -e "    },"
    echo -e "    {"
    echo -e "      \"نام\": \"Portainer\","
    echo -e "      \"آدرس\": \"http://$SERVER_IP:$PORTAINER_PORT\","
    echo -e "      \"نام کاربری\": \"N/A (اولین ورود رمز تنظیم کنید)\","
    echo -e "      \"رمز\": \"N/A (اولین ورود رمز تنظیم کنید)\""
    echo -e "    }"
    echo -e "  ],"
    echo -e "  \"زمان نصب\": \"$(date)\""
    echo -e "}"
    echo -e "➖ نصب با موفقیت انجام شد!")
    send_telegram "$REPORT"
else
    echo "❌ Problem detected: SSH or Docker is not running."
    send_telegram "❌ مشکلی در سرور وجود دارد: SSH یا Docker فعال نیست - $(hostname) در $(date)"
    exit 1
fi

# ری‌استارت Portainer برای باز کردن پنجره تنظیم رمز
echo "🔄 Restarting Portainer to reset timeout..."
sudo docker restart portainer
echo "✅ Portainer restarted! Please access http://$SERVER_IP:$PORTAINER_PORT within 5 minutes to set the initial password."

echo "✅ Secure setup completed successfully at $(date)!"
exit 0
