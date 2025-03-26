#!/bin/bash

# =============================================
# تنظیمات اصلی
# =============================================
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"
NEW_USER="bigpython"
SSH_PORT="9011"
CODE_SERVER_PORT="1010"  # پورت اختصاصی برای Code-Server
NETDATA_PORT="9001"
CROWDSEC_DASHBOARD_PORT="3000"
PORTAINER_PORT="9000"
NGINX_PROXY_MANAGER_PORT="81"
CODE_SERVER_PASSWORD="114aa2650b0db5509f36f4fc"  # پسورد موقت - بعد از نصب تغییر دهید
PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8J++ag0NtV/AaQU9mF7X8qSKGrOy2Wu1eJISg72Zfs bigpython@TradePC"

# لیست پورت‌های باز
PORTS_TO_OPEN=("80" "443" "$SSH_PORT" "$CODE_SERVER_PORT" "$NETDATA_PORT" "$CROWDSEC_DASHBOARD_PORT" "$PORTAINER_PORT" "$NGINX_PROXY_MANAGER_PORT")
RESERVED_PORTS=("1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080")

# =============================================
# توابع کمکی
# =============================================

# تابع ارسال گزارش به تلگرام
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=Markdown" >/dev/null 2>&1 || echo "⚠️ خطا در ارسال پیام به تلگرام"
}

# تابع بررسی موفقیت عملیات
check_success() {
    if [ $? -eq 0 ]; then
        echo "✅ $1"
        send_telegram "✅ $1"
    else
        echo "❌ $1"
        send_telegram "❌ خطا در: $1"
        exit 1
    fi
}

# =============================================
# شروع فرآیند نصب
# =============================================

# گزارش شروع
send_telegram "🔥 شروع فرآیند پیکربندی سرور در $(date)"

# 1. به‌روزرسانی سیستم
echo "🔄 در حال بروزرسانی سیستم..."
apt update && apt upgrade -y
check_success "بروزرسانی سیستم انجام شد"

# 2. ایجاد کاربر جدید
echo "🔄 ایجاد کاربر $NEW_USER..."
adduser --disabled-password --gecos "" "$NEW_USER"
usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER"

# تنظیمات SSH
mkdir -p "/home/$NEW_USER/.ssh"
echo "$PUBLIC_KEY" > "/home/$NEW_USER/.ssh/authorized_keys"
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.ssh"
chmod 700 "/home/$NEW_USER/.ssh"
chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"

# تنظیمات sshd_config
cat <<EOL > /etc/ssh/sshd_config
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
AuthenticationMethods publickey
AllowUsers $NEW_USER
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
EOL

systemctl restart sshd
check_success "تنظیمات SSH برای کاربر $NEW_USER"

# =============================================
# نصب Docker و Docker Compose
# =============================================
echo "🔄 نصب Docker و Docker Compose..."
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
check_success "Docker و Docker Compose نصب شدند"

# =============================================
# نصب و تنظیم Portainer
# =============================================
echo "🔄 نصب Portainer..."
docker volume create portainer_data
docker run -d --name portainer -p "$PORTAINER_PORT:9000" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    --restart unless-stopped \
    portainer/portainer-ce:latest
check_success "Portainer نصب شد"

# =============================================
# نصب و تنظیم Nginx Proxy Manager
# =============================================
echo "🔄 نصب Nginx Proxy Manager..."
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
check_success "Nginx Proxy Manager نصب شد"

# =============================================
# نصب و تنظیم Netdata
# =============================================
# نصب و تنظیم Netdata
apt install -y netdata

# تنظیمات دسترسی
sudo tee -a /etc/netdata/netdata.conf <<EOL
[web]
    bind to = 0.0.0.0
    allow connections from = *
EOL

# تنظیم مجوزها
sudo chown -R netdata:netdata /usr/share/netdata/web
sudo chmod -R 0755 /usr/share/netdata/web

# فعال‌سازی سرویس
sudo systemctl enable --now netdata
sudo systemctl restart netdata

# باز کردن پورت در فایروال
sudo ufw allow 9001/tcp

# =============================================
# تنظیم فایروال
# =============================================
echo "🔄 تنظیم فایروال..."
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing

for port in "${PORTS_TO_OPEN[@]}"; do
    ufw allow "$port/tcp"
done

ufw --force enable
check_success "فایروال تنظیم شد"

# =============================================
# نصب و تنظیم CrowdSec
# =============================================
echo "🔄 نصب CrowdSec..."
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt install -y crowdsec crowdsec-firewall-bouncer-iptables
systemctl enable --now crowdsec
check_success "CrowdSec نصب شد"

# =============================================
# نصب و تنظیم Code-Server با رفع خطاهای دسترسی
# =============================================
echo "🔄 نصب Code-Server با رفع خطاهای دسترسی..."

# نصب Code-Server
curl -fsSL https://code-server.dev/install.sh | sh

# تنظیم دسترسی‌های لازم
sudo setcap cap_net_bind_service=+ep $(readlink -f $(which node))
mkdir -p "/home/$NEW_USER/.config/code-server"
mkdir -p "/home/$NEW_USER/.local/share/code-server"
chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.config"
chown -R "$NEW_USER:$NEW_USER" "/home/$NEW_USER/.local"

# ایجاد سرویس سیستم‌دی اختصاصی
cat <<EOL | sudo tee /etc/systemd/system/code-server.service >/dev/null
[Unit]
Description=Code-Server
After=network.target

[Service]
Type=simple
User=$NEW_USER
Group=$NEW_USER
WorkingDirectory=/home/$NEW_USER
Environment="PATH=/usr/bin"
ExecStart=/usr/bin/code-server --bind-addr 0.0.0.0:$CODE_SERVER_PORT
Restart=always
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOL

# تنظیم کانفیگ
cat <<EOL > "/home/$NEW_USER/.config/code-server/config.yaml"
bind-addr: 0.0.0.0:$CODE_SERVER_PORT
auth: password
password: $CODE_SERVER_PASSWORD
cert: false
EOL

# فعال‌سازی سرویس
sudo systemctl daemon-reload
sudo systemctl enable --now code-server.service
check_success "Code-Server با موفقیت نصب و تنظیم شد"

# =============================================
# نصب ابزارهای جانبی
# =============================================
echo "🔄 نصب ابزارهای جانبی..."
apt install -y \
    wget curl net-tools iperf3 \
    htop glances tmux \
    rsync vim nano unzip zip \
    build-essential git lftp \
    clamav clamav-daemon rkhunter lynis \
    auditd tcpdump nmap \
    python3-pip python3-venv python3-dev

systemctl enable --now auditd
check_success "ابزارهای جانبی نصب شدند"

# =============================================
# تنظیمات امنیتی نهایی
# =============================================
echo "🔄 اعمال تنظیمات امنیتی..."
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
check_success "تنظیمات امنیتی اعمال شد"

# =============================================
# ریستارت نهایی سرویس‌ها
# =============================================
echo "🔄 ریستارت نهایی سرویس‌ها..."
services_to_restart=(
    "docker"
    "code-server.service"
    "netdata"
    "crowdsec"
)

for service in "${services_to_restart[@]}"; do
    systemctl restart "$service" 2>/dev/null || docker restart "$service"
    check_success "ریستارت $service"
done

# =============================================
# گزارش نهایی
# =============================================
SERVER_IP=$(curl -s -4 icanhazip.com)
LOCATION=$(curl -s http://ip-api.com/line/$SERVER_IP?fields=country,city,isp)

REPORT="
🚀 **گزارش نهایی پیکربندی سرور**  
⏳ زمان اجرا: \`$(date)\`  

🔹 **مشخصات سرور:**  
   - نام سرور: \`$(hostname)\`  
   - آدرس IP: \`$SERVER_IP\`  
   - موقعیت مکانی: \`$LOCATION\`  

🔹 **وضعیت سرویس‌ها:**  
   - 🐳 Portainer: [لینک]($SERVER_IP:$PORTAINER_PORT) | وضعیت: \`$(docker inspect -f '{{.State.Status}}' portainer)\`  
   - 🌐 Nginx Proxy Manager: [لینک]($SERVER_IP:$NGINX_PROXY_MANAGER_PORT)  
   - 💻 Code-Server: [لینک]($SERVER_IP:$CODE_SERVER_PORT) | وضعیت: \`$(systemctl is-active code-server.service)\`  
   - 📊 Netdata: [لینک]($SERVER_IP:$NETDATA_PORT) | وضعیت: \`$(systemctl is-active netdata)\`  
   - 🛡️ CrowdSec: [لینک]($SERVER_IP:$CROWDSEC_DASHBOARD_PORT) | وضعیت: \`$(systemctl is-active crowdsec)\`  

🔹 **دسترسی SSH:**  
   - پورت: \`$SSH_PORT\`  
   - کاربر: \`$NEW_USER\`  
   - روش احراز: 🔑 کلید عمومی  

🔹 **پورت‌های باز:**  
\`${PORTS_TO_OPEN[*]}\`  

📌 **نکات مهم:**  
- برای Portainer پس از اولین ورود، رمز عبور را تغییر دهید.  
- برای Code-Server از رمز \`$CODE_SERVER_PASSWORD\` استفاده کنید (توصیه می‌شود تغییر دهید).  
- تمام پورت‌های غیرضروری مسدود شده‌اند.  
"

send_telegram "$REPORT"
check_success "ارسال گزارش نهایی"

echo "✅ پیکربندی سرور با موفقیت انجام شد!"
exit 0
