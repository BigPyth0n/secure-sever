#!/bin/bash

# تنظیمات اولیه
TELEGRAM_BOT_TOKEN="<YOUR_TELEGRAM_BOT_TOKEN>"
TELEGRAM_CHAT_ID="<YOUR_TELEGRAM_CHAT_ID>"
NEW_USER="bigpython"
SSH_PORT="9011"
CODE_SERVER_PORT="1010"
NETDATA_PORT="9001"
CROWDSEC_DASHBOARD_PORT="3000"
PORTAINER_PORT="9000"
CODE_SERVER_PASSWORD="<YOUR_CODE_SERVER_PASSWORD>"
PUBLIC_KEY="<YOUR_SSH_PUBLIC_KEY>"
PORTS_TO_OPEN=("80" "443" "$SSH_PORT" "$CODE_SERVER_PORT" "$NETDATA_PORT" "$CROWDSEC_DASHBOARD_PORT" "$PORTAINER_PORT")
RESERVED_PORTS=("1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080")

# بروزرسانی سیستم
apt update && apt upgrade -y

# ایجاد کاربر جدید
adduser --disabled-password --gecos "" "$NEW_USER"
usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER"
mkdir -p "/home/$NEW_USER/.ssh"
echo "$PUBLIC_KEY" > "/home/$NEW_USER/.ssh/authorized_keys"
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.ssh"
chmod 700 "/home/$NEW_USER/.ssh"
chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"

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

# نصب Docker و Docker Compose
apt install -y apt-transport-https ca-certificates curl software-properties-common
dpkg --configure -a
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu jammy stable"
apt update && apt install -y docker-ce
systemctl enable --now docker
usermod -aG docker "$NEW_USER"
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# نصب Portainer
docker volume create portainer_data
docker run -d --name portainer -p "$PORTAINER_PORT:9000" -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data --restart unless-stopped portainer/portainer-ce:latest

# تنظیم فایروال UFW
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
for port in "${PORTS_TO_OPEN[@]}"; do
    ufw allow "$port/tcp"
done
ufw --force enable

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

# تنظیم Code-Server
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

# رفع مشکل Netdata
chown -R netdata:netdata /usr/share/netdata/web
systemctl restart netdata

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

# ارسال گزارش به تلگرام
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=Markdown" >/dev/null 2>&1 || echo "⚠️ خطا در ارسال پیام به تلگرام"
}
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

🔹 **پورت‌های باز:**
   - \`${PORTS_TO_OPEN[*]}\`
🔹 **پورت‌های رزرو‌شده:**
   - \`${RESERVED_PORTS[*]}\`

🔹 **وضعیت امنیت:**
   - فایروال UFW: ✅ فعال
   - CrowdSec و Fail2Ban: ✅ فعال و نظارت بر حملات
"
send_telegram "$REPORT"

exit 0
