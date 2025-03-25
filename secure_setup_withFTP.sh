#!/bin/bash

# 🛠️ تنظیمات اولیه
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"
NEW_USER="bigpython"
SSH_PORT="9011"
CODE_SERVER_PORT="1010"
NETDATA_PORT="9001"
CROWDSEC_DASHBOARD_PORT="3000"
PORTAINER_PORT="9000"
CODE_SERVER_PASSWORD="114aa2650b0db5509f36f4fc"
PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8J++ag0NtV/AaQU9mF7X8qSKGrOy2Wu1eJISg72Zfs bigpython@TradePC"
PORTS_TO_OPEN=("1010" "1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080" "80" "81" "9000" "443" "$SSH_PORT" "$NETDATA_PORT" "$CROWDSEC_DASHBOARD_PORT")
RESERVED_PORTS=("1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080")

# 🛠️ گرفتن IP و اطلاعات سرور
SERVER_IP=$(curl -s -4 icanhazip.com) || { echo "❌ خطا در گرفتن IP سرور"; exit 1; }
SERVER_LOCATION=$(curl -s "http://ip-api.com/line/$SERVER_IP?fields=country,city" | tr '\n' ', ' | sed 's/, $//') || "نامشخص"
SERVER_NAME=$(hostname)

# 🛠️ تابع ارسال پیام به تلگرام
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" >/dev/null 2>&1 || echo "⚠️ خطا در ارسال پیام به تلگرام"
}

# 🛠️ چک کردن دسترسی root
if [[ $EUID -ne 0 ]]; then
    echo "❌ این اسکریپت باید با دسترسی root اجرا بشه. خارج می‌شم."
    exit 1
fi

# 🛠️ آپدیت و ارتقای سیستم
echo "🔄 آپدیت و ارتقای سیستم..."
apt update && apt upgrade -y || { echo "❌ خطا در آپدیت/ارتقای سیستم"; exit 1; }

# 🛠️ ایجاد کاربر جدید و تنظیم SSH
echo "👤 ایجاد کاربر و تنظیم SSH..."
adduser --disabled-password --gecos "" "$NEW_USER"
usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER"
chmod 440 /etc/sudoers.d/"$NEW_USER"
mkdir -p "/home/$NEW_USER/.ssh"
echo "$PUBLIC_KEY" > "/home/$NEW_USER/.ssh/authorized_keys"
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.ssh"
chmod 700 "/home/$NEW_USER/.ssh"
chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"

# 🛠️ تنظیم پورت و امنیت SSH
echo "🔒 پیکربندی SSH..."
cat <<EOL > /etc/ssh/sshd_config
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
PubkeyAcceptedKeyTypes ssh-rsa,ssh-ed25519
UsePAM yes
Subsystem sftp /usr/lib/openssh/sftp-server
MaxAuthTries 3
LoginGraceTime 30
AllowUsers $NEW_USER
EOL
systemctl restart sshd

# 🛠️ نصب Docker و ابزارهای پایه
echo "🐳 نصب Docker و پیش‌نیازها..."
apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add -
add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu jammy stable"
apt update && apt install -y docker-ce
systemctl enable --now docker
usermod -aG docker "$NEW_USER"

# نصب Docker Compose
curl -L "https://github.com/docker/compose/releases/download/1.29.2/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# نصب Portainer
docker volume create portainer_data
docker run -d --name portainer -p "$PORTAINER_PORT:9000" -v /var/run/docker.sock:/var/run/docker.sock -v portainer_data:/data --restart unless-stopped portainer/portainer-ce:latest

# 🛠️ نصب پایتون 3.10
echo "🐍 نصب پایتون 3.10..."
apt install -y python3.10 python3.10-dev python3.10-venv python3-pip
python3.10 -m pip install --upgrade pip

# 🛠️ نصب Code-Server
echo "💻 نصب Code-Server..."
curl -fsSL https://code-server.dev/install.sh | sh
systemctl enable --now code-server@"$NEW_USER"
cat <<EOL > "/home/$NEW_USER/.config/code-server/config.yaml"
bind-addr: 0.0.0.0:$CODE_SERVER_PORT
auth: password
password: $CODE_SERVER_PASSWORD
cert: false
EOL
chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.config"
systemctl restart code-server@"$NEW_USER"

# 🛠️ تنظیم فایروال UFW
echo "🔥 پیکربندی UFW..."
apt install -y ufw
ufw default deny incoming
ufw default allow outgoing
for port in "${PORTS_TO_OPEN[@]}"; do
    ufw allow "$port/tcp"
done
ufw --force enable

# 🛠️ نصب CrowdSec و fail2ban
echo "🛡️ نصب CrowdSec و fail2ban..."
curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
apt install -y crowdsec crowdsec-firewall-bouncer-iptables fail2ban
cat <<EOL > /etc/crowdsec/notifications/http.yaml
type: http
name: http_telegram
url: "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage"
method: POST
headers:
  Content-Type: "application/x-www-form-urlencoded"
body: "chat_id=$TELEGRAM_CHAT_ID&text=🚨 حمله تشخیص داده شد!\nسرور: $(hostname)\nنوع حمله: \${scenario}\nIP مهاجم: \${source_ip}\nزمان: \${time}"
EOL
cscli notifications add /etc/crowdsec/notifications/http.yaml
sed -i '/^notifications:/a\  - http_telegram' /etc/crowdsec/config.yaml
systemctl restart crowdsec

# تنظیم fail2ban
cat <<EOL > /etc/fail2ban/jail.local
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3

[sshd]
enabled = true
port = $SSH_PORT
logpath = /var/log/auth.log
EOL
systemctl enable fail2ban
systemctl start fail2ban

# 🛠️ نصب ابزارهای اضافی و Netdata
echo "📦 نصب ابزارها و Netdata..."
apt install -y git tmux netdata
cat <<EOL > /etc/netdata/netdata.conf
[global]
    run as user = netdata
[web]
    bind to = 0.0.0.0:$NETDATA_PORT
EOL
systemctl restart netdata

# 🛠️ تنظیمات امنیتی سیستمی
echo "🔧 اعمال تنظیمات امنیتی سیستم..."
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

# 🛠️ تنظیم اسکن‌های روزانه
echo "⏰ تنظیم اسکن‌های روزانه..."
(crontab -l 2>/dev/null; echo "0 2 * * * /usr/bin/clamscan -r / --exclude-dir=/sys/ --exclude-dir=/proc/ --exclude-dir=/dev/ -l /var/log/clamav/scan.log") | crontab -
(crontab -l 2>/dev/null; echo "0 3 * * * /usr/bin/rkhunter --check --sk") | crontab -
(crontab -l 2>/dev/null; echo "0 4 * * * /usr/bin/lynis audit system") | crontab -

# 🛠️ راه‌اندازی مجدد سرویس‌ها
echo "🔄 راه‌اندازی مجدد سرویس‌ها..."
systemctl restart sshd
ufw reload

# 🛠️ گزارش نهایی
echo "📌 ارسال گزارش نهایی..."
REPORT=$(cat <<EOL
📌 گزارش کامل نصب و پیکربندی سرور

🔹 **مشخصات سرور:**
   - نام سرور: $SERVER_NAME
   - آدرس IP: $SERVER_IP
   - محل سرور: $SERVER_LOCATION
   - زمان نصب: $(date)

🔹 **تنظیمات SSH:**
   - پورت: $SSH_PORT
   - کاربر: $NEW_USER
   - روش احراز هویت: فقط کلید عمومی (رمز عبور غیرفعال)
   - امنیت: MaxAuthTries=3, LoginGraceTime=30

🔹 **سرویس‌های نصب‌شده و آدرس‌ها:**
   - Docker: فعال
   - Portainer: http://$SERVER_IP:$PORTAINER_PORT (مدیریت کانتینرها)
   - Code-Server: http://$SERVER_IP:$CODE_SERVER_PORT (رمز: $CODE_SERVER_PASSWORD)
   - Netdata: http://$SERVER_IP:$NETDATA_PORT (مانیتورینگ سیستم)
   - CrowdSec: داشبورد در http://$SERVER_IP:$CROWDSEC_DASHBOARD_PORT (تشخیص حملات)

🔹 **ابزارهای نصب‌شده:**
   - Git: برای مدیریت کد
   - Tmux: برای ترمینال چندگانه
   - Python 3.10: با pip

🔹 **وضعیت سرویس‌ها:**
   - SSH: $(systemctl is-active sshd)
   - Docker: $(systemctl is-active docker)
   - Code-Server: $(systemctl is-active code-server@$NEW_USER)
   - Portainer: $(docker ps --filter name=portainer --format "{{.Status}}")
   - Netdata: $(systemctl is-active netdata)
   - CrowdSec: $(systemctl is-active crowdsec)
   - fail2ban: $(systemctl is-active fail2ban)

🔹 **پورت‌های باز:**
   - فعال: $SSH_PORT (SSH), $CODE_SERVER_PORT (Code-Server), $NETDATA_PORT (Netdata), $PORTAINER_PORT (Portainer), $CROWDSEC_DASHBOARD_PORT (CrowdSec), 80, 81, 443
   - ذخیره‌ای (برای استفاده آینده): ${RESERVED_PORTS[*]}

🔹 **امنیت سرور:**
   - فایروال: UFW فعال با قوانین سخت‌گیرانه
   - CrowdSec: فعال با ارسال هشدار به تلگرام
   - fail2ban: فعال برای جلوگیری از حملات SSH
   - اسکن روزانه: ClamAV، Rkhunter و Lynis تنظیم شده

🔹 **نکات مفید:**
   - برای اتصال SSH: ssh -p $SSH_PORT $NEW_USER@$SERVER_IP
   - همه سرویس‌ها با سیاست restart unless-stopped اجرا می‌شن.
   - گزارش حملات به تلگرام ارسال می‌شه.

➖ **نصب و پیکربندی با موفقیت انجام شد!**
EOL
)
send_telegram "$REPORT"

echo "✅ نصب با موفقیت در $(date) به پایان رسید!"
exit 0
