#!/bin/bash

# تنظیمات اولیه
TELEGRAM_BOT_TOKEN="1234567890:YOUR_TELEGRAM_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID="-123456789"
NEW_USER="bigpython"
SSH_PORT="9011"
CODE_SERVER_PORT="1010"
NETDATA_PORT="9001"
CROWDSEC_DASHBOARD_PORT="3000"
PORTAINER_PORT="9000"
NGINX_PROXY_MANAGER_PORT="81"
CODE_SERVER_PASSWORD="YOUR_CODE_SERVER_PASSWORD"
PUBLIC_KEY="YOUR_SSH_PUBLIC_KEY_HERE"
PORTS_TO_OPEN=("80" "443" "$SSH_PORT" "$CODE_SERVER_PORT" "$NETDATA_PORT" "$CROWDSEC_DASHBOARD_PORT" "$PORTAINER_PORT" "$NGINX_PROXY_MANAGER_PORT")
RESERVED_PORTS=("1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080")

# تابع ارسال پیام به تلگرام
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=Markdown" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "⚠️ خطا در ارسال پیام به تلگرام"
        exit 1
    fi
}

# بررسی پیش‌نیازها
if ! command -v curl >/dev/null 2>&1; then
    apt update && apt install -y curl || { send_telegram "❌ خطا در نصب curl"; exit 1; }
fi

# بروزرسانی سیستم
send_telegram "🔄 شروع بروزرسانی سیستم..."
apt update && apt upgrade -y || { send_telegram "❌ خطا در بروزرسانی سیستم"; exit 1; }

# ایجاد کاربر جدید
send_telegram "👤 ایجاد کاربر جدید: $NEW_USER"
adduser --disabled-password --gecos "" "$NEW_USER" || { send_telegram "❌ خطا در ایجاد کاربر"; exit 1; }
usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER"
mkdir -p "/home/$NEW_USER/.ssh"
echo "$PUBLIC_KEY" > "/home/$NEW_USER/.ssh/authorized_keys"
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.ssh"
chmod 700 "/home/$NEW_USER/.ssh"
chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"

# تنظیمات SSH
send_telegram "🔑 تنظیم SSH با پورت $SSH_PORT"
cat <<EOL > /etc/ssh/sshd_config
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
MaxAuthTries 3
LoginGraceTime 30
AllowUsers $NEW_USER
EOL
systemctl restart sshd || { send_telegram "❌ خطا در راه‌اندازی SSH"; exit 1; }

# نصب Docker و Docker Compose
send_telegram "🐳 نصب Docker و Docker Compose"
apt install -y apt-transport-https ca-certificates curl software-properties-common || { send_telegram "❌ خطا در نصب پیش‌نیازهای Docker"; exit 1; }
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu jammy stable"
apt update && apt install -y docker-ce || { send_telegram "❌ خطا در نصب Docker"; exit 1; }
systemctl enable --now docker
usermod -aG docker "$NEW_USER"
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# نصب Portainer
send_telegram "📦 نصب Portainer روی پورت $PORTAINER_PORT"
docker volume create portainer_data
docker run -d --name portainer -p "$PORTAINER_PORT:9000" -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data --restart unless-stopped portainer/portainer-ce:latest || { send_telegram "❌ خطا در نصب Portainer"; exit 1; }

# نصب Nginx Proxy Manager
send_telegram "🌐 نصب Nginx Proxy Manager"
mkdir -p /opt/nginx-proxy-manager
cat <<EOL > /opt/nginx-proxy-manager/docker-compose.yml
version: '3'
services:
  app:
    image: 'jc21/nginx-proxy-manager:latest'
    restart: unless-stopped
    ports:
      - '80:80'
      - '81:81'
      - '443:443'
    volumes:
      - ./data:/data
      - ./letsencrypt:/etc/letsencrypt
EOL
cd /opt/nginx-proxy-manager
docker-compose up -d || { send_telegram "❌ خطا در نصب Nginx Proxy Manager"; exit 1; }

# نصب Netdata
send_telegram "📊 نصب Netdata روی پورت $NETDATA_PORT"
bash <(curl -Ss https://my-netdata.io/kickstart.sh) --no-updates --stable-channel --disable-telemetry || { send_telegram "❌ خطا در نصب Netdata"; exit 1; }
chown -R netdata:netdata /usr/share/netdata/web
systemctl restart netdata || { send_telegram "❌ خطا در راه‌اندازی Netdata"; exit 1; }

# تنظیم فایروال UFW
send_telegram "🔥 تنظیم فایروال UFW"
apt install -y ufw || { send_telegram "❌ خطا در نصب UFW"; exit 1; }
ufw default deny incoming
ufw default allow outgoing
for port in "${PORTS_TO_OPEN[@]}"; do
    ufw allow "$port/tcp"
done
ufw --force enable

# نصب CrowdSec و Fail2Ban
send_telegram "🛡️ نصب CrowdSec و Fail2Ban"
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt install -y crowdsec crowdsec-firewall-bouncer-iptables fail2ban || { send_telegram "❌ خطا در نصب CrowdSec یا Fail2Ban"; exit 1; }
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
systemctl restart fail2ban || { send_telegram "❌ خطا در راه‌اندازی Fail2Ban"; exit 1; }

# نصب Code-Server
send_telegram "💻 نصب Code-Server روی پورت $CODE_SERVER_PORT"
curl -fsSL https://code-server.dev/install.sh | sh || { send_telegram "❌ خطا در نصب Code-Server"; exit 1; }
systemctl enable --now code-server@"$NEW_USER"
mkdir -p "/home/$NEW_USER/.config/code-server"
cat <<EOL > "/home/$NEW_USER/.config/code-server/config.yaml"
bind-addr: 0.0.0.0:$CODE_SERVER_PORT
auth: password
password: $CODE_SERVER_PASSWORD
cert: false
EOL
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.config"
systemctl restart code-server@"$NEW_USER" || { send_telegram "❌ خطا در راه‌اندازی Code-Server"; exit 1; }

# تنظیمات امنیتی
send_telegram "🔒 اعمال تنظیمات امنیتی sysctl"
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
sysctl -p || { send_telegram "❌ خطا در اعمال تنظیمات sysctl"; exit 1; }

# ارسال گزارش نهایی
REPORT="📌 **گزارش نهایی پیکربندی سرور**

🔹 **مشخصات سرور:**
   - نام سرور: \`$(hostname)\`
   - آدرس IP: \`$(curl -s -4 icanhazip.com)\`
   - موقعیت مکانی: \`$(curl -s http://ip-api.com/line/$(curl -s -4 icanhazip.com)?fields=country,city)\`

🔹 **تنظیمات SSH:**
   - پورت: \`$SSH_PORT\`
   - احراز هویت: **فقط کلید عمومی**
   - کاربر مجاز: \`$NEW_USER\`

🔹 **سرویس‌های نصب‌شده:**
   - Docker ✅
   - Portainer: [لینک](http://$(curl -s -4 icanhazip.com):$PORTAINER_PORT)
   - Code-Server: [لینک](http://$(curl -s -4 icanhazip.com):$CODE_SERVER_PORT)
   - Netdata: [لینک](http://$(curl -s -4 icanhazip.com):$NETDATA_PORT)
   - CrowdSec: [لینک](http://$(curl -s -4 icanhazip.com):$CROWDSEC_DASHBOARD_PORT)
   - Fail2Ban ✅
   - Nginx Proxy Manager: [لینک](http://$(curl -s -4 icanhazip.com):$NGINX_PROXY_MANAGER_PORT)

🔹 **پورت‌های باز:**
   - \`${PORTS_TO_OPEN[*]}\`
🔹 **پورت‌های رزرو‌شده:**
   - \`${RESERVED_PORTS[*]}\`

🔹 **وضعیت امنیت:**
   - فایروال UFW: ✅ فعال
   - CrowdSec و Fail2Ban: ✅ فعال و نظارت بر حملات

✅ **پیکربندی با موفقیت انجام شد!**"
send_telegram "$REPORT"

echo "🎉 اسکریپت با موفقیت اجرا شد!"
exit 0
