#!/bin/bash

# تنظیمات اصلی
TELEGRAM_BOT_TOKEN="<YOUR_TELEGRAM_BOT_TOKEN>"
TELEGRAM_CHAT_ID="<YOUR_TELEGRAM_CHAT_ID>"
NEW_USER="bigpython"
SSH_PORT="9011"
CODE_SERVER_PORT="1010"
NETDATA_PORT="9001"
CROWDSEC_DASHBOARD_PORT="3000"
PORTAINER_PORT="9000"
NGINX_PROXY_MANAGER_PORT="81"
CODE_SERVER_PASSWORD="<YOUR_CODE_SERVER_PASSWORD>"
PUBLIC_KEY="<YOUR_SSH_PUBLIC_KEY>"

# لیست پورت‌های باز
PORTS_TO_OPEN=("80" "443" "$SSH_PORT" "$CODE_SERVER_PORT" "$NETDATA_PORT" "$CROWDSEC_DASHBOARD_PORT" "$PORTAINER_PORT" "$NGINX_PROXY_MANAGER_PORT")
RESERVED_PORTS=("1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080")

# تابع برای ارسال گزارش به تلگرام
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=Markdown" >/dev/null 2>&1 || echo "⚠️ خطا در ارسال پیام به تلگرام"
}

# تابع برای بررسی موفقیت عملیات
check_success() {
    if [ $? -eq 0 ]; then
        echo "✅ $1"
    else
        echo "❌ $1"
        send_telegram "خطا در عملیات: $1"
        exit 1
    fi
}

# گزارش شروع
send_telegram "🔥 شروع فرآیند پیکربندی سرور در $(date)"

# بروزرسانی سیستم
apt update && apt upgrade -y
check_success "بروزرسانی سیستم"

# ایجاد کاربر جدید
adduser --disabled-password --gecos "" "$NEW_USER"
check_success "ایجاد کاربر $NEW_USER"

usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER"
mkdir -p "/home/$NEW_USER/.ssh"
echo "$PUBLIC_KEY" > "/home/$NEW_USER/.ssh/authorized_keys"
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.ssh"
chmod 700 "/home/$NEW_USER/.ssh"
chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
check_success "تنظیمات SSH برای کاربر $NEW_USER"

# تنظیمات SSH
cat <<EOL > /etc/ssh/sshd_config
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
MaxAuthTries 3
LoginGraceTime 30
AllowUsers $NEW_USER
EOL

systemctl restart sshd
check_success "تنظیمات SSH"

# نصب Docker و Docker Compose
apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null

apt update && apt install -y docker-ce docker-ce-cli containerd.io
systemctl enable --now docker
usermod -aG docker "$NEW_USER"

# نصب Docker Compose
DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose
ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
check_success "نصب Docker و Docker Compose"

# نصب Portainer
docker volume create portainer_data
docker run -d --name portainer -p "$PORTAINER_PORT:9000" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    --restart unless-stopped \
    portainer/portainer-ce:latest
check_success "نصب Portainer"

# نصب Nginx Proxy Manager
mkdir -p /var/docker/nginx-proxy-manager/{data,letsencrypt}
docker run -d \
    --name nginx-proxy-manager \
    -p 80:80 \
    -p 443:443 \
    -p "$NGINX_PROXY_MANAGER_PORT:81" \
    -v /var/docker/nginx-proxy-manager/data:/data \
    -v /var/docker/nginx-proxy-manager/letsencrypt:/etc/letsencrypt \
    --restart unless-stopped \
    jc21/nginx-proxy-manager:latest
check_success "نصب Nginx Proxy Manager"

# نصب و تنظیم Netdata
apt install -y netdata
systemctl enable --now netdata
chown -R netdata:netdata /usr/share/netdata/web
systemctl restart netdata
check_success "نصب و تنظیم Netdata"

# تنظیم فایروال
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing

for port in "${PORTS_TO_OPEN[@]}"; do
    ufw allow "$port/tcp"
done

ufw --force enable
check_success "تنظیمات فایروال"

# نصب CrowdSec و fail2ban
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt install -y crowdsec crowdsec-firewall-bouncer-iptables fail2ban

cat <<EOL > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 10800
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/auth.log
EOL

systemctl restart fail2ban
check_success "نصب CrowdSec و fail2ban"

# نصب و تنظیم Code-Server
curl -fsSL https://code-server.dev/install.sh | sh
systemctl enable --now code-server@"$NEW_USER"

mkdir -p "/home/$NEW_USER/.config/code-server"
cat <<EOL > "/home/$NEW_USER/.config/code-server/config.yaml"
bind-addr: 0.0.0.0:$CODE_SERVER_PORT
auth: password
password: $CODE_SERVER_PASSWORD
cert: false
EOL

chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.config"
systemctl restart code-server@"$NEW_USER"
check_success "نصب و تنظیم Code-Server"

# تنظیمات امنیتی
cat <<EOL >> /etc/sysctl.conf
net.ipv4.tcp_syncookies=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
kernel.yama.ptrace_scope=1
EOL

sysctl -p
check_success "تنظیمات امنیتی"

# نصب ابزارهای جانبی
apt install -y \
    wget curl net-tools iperf3 \
    htop glances tmux \
    rsync vim nano unzip zip \
    build-essential git lftp \
    clamav clamav-daemon rkhunter lynis \
    auditd tcpdump nmap \
    python3-pip python3-venv python3-dev

systemctl enable --now auditd
check_success "نصب ابزارهای جانبی"

# گزارش نهایی
SERVER_IP=$(curl -s -4 icanhazip.com)
LOCATION=$(curl -s http://ip-api.com/line/$SERVER_IP?fields=country,city,isp)

REPORT="
🚀 **گزارش نهایی پیکربندی سرور**  
⏳ زمان اجرا: \`$(date)\`  

🔹 **مشخصات سرور:**  
   - نام سرور: \`$(hostname)\`  
   - آدرس IP: \`$SERVER_IP\`  
   - موقعیت مکانی: \`$LOCATION\`  

🔹 **تنظیمات کاربری:**  
   - کاربر اصلی: \`$NEW_USER\`  
   - دسترسی root: ❌ غیرفعال  
   - گروه‌های کاربر: \`$(groups $NEW_USER)\`  

🔹 **سرویس‌های نصب‌شده:**  
   - 🐳 Docker + Portainer: [مدیریت]($SERVER_IP:$PORTAINER_PORT)  
   - 🔄 Nginx Proxy Manager: [مدیریت]($SERVER_IP:$NGINX_PROXY_MANAGER_PORT)  
   - 💻 Code-Server: [دسترسی]($SERVER_IP:$CODE_SERVER_PORT)  
   - 📊 Netdata: [مانیتورینگ]($SERVER_IP:$NETDATA_PORT)  
   - 🛡️ CrowdSec: [داشبورد]($SERVER_IP:$CROWDSEC_DASHBOARD_PORT)  

🔹 **وضعیت امنیتی:**  
   - فایروال: ✅ (پورت‌های باز: ${PORTS_TO_OPEN[*]})  
   - Fail2Ban: ✅ (وضعیت: \`$(fail2ban-client status sshd | grep 'Currently banned')\`)  
   - اسکنر امنیتی: Lynis + ClamAV  

🔹 **پورت‌های رزرو شده:**  
\`${RESERVED_PORTS[*]}\`  

📌 **نکات مهم:**  
- برای Nginx Proxy Manager، پس از اولین ورود با \`admin@example.com\` و رمز \`changeme\` وارد شوید.  
- کد سرور با رمز \`$CODE_SERVER_PASSWORD\` محافظت می‌شود.  
- تمامی پورت‌های غیرضروری مسدود شده‌اند.  
"

send_telegram "$REPORT"
check_success "ارسال گزارش نهایی"

echo "✅ پیکربندی سرور با موفقیت انجام شد!"
exit 0
