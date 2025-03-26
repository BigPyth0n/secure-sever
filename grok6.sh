#!/bin/bash

# =============================================
# تنظیمات اصلی
# =============================================
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"  # اگر گروهه، به "-59941862" تغییر بده
NEW_USER="bigpython"
SSH_PORT="9011"
CODE_SERVER_PORT="1010"
NETDATA_PORT="9001"
CROWDSEC_DASHBOARD_PORT="3000"
PORTAINER_PORT="9000"
NGINX_PROXY_MANAGER_PORT="81"
CODE_SERVER_PASSWORD="114aa2650b0db5509f36f4fc"  # پس از نصب تغییر دهید
PUBLIC_KEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIO8J++ag0NtV/AaQU9mF7X8qSKGrOy2Wu1eJISg72Zfs bigpython@TradePC"

# لیست پورت‌ها
PORTS_TO_OPEN=("80" "443" "$SSH_PORT" "$CODE_SERVER_PORT" "$NETDATA_PORT" "$CROWDSEC_DASHBOARD_PORT" "$PORTAINER_PORT" "$NGINX_PROXY_MANAGER_PORT")
RESERVED_PORTS=("1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080")

# آرایه برای ذخیره وضعیت سرویس‌ها
declare -A SERVICE_STATUS

# =============================================
# توابع کمکی
# =============================================

# تابع ارسال گزارش به تلگرام
send_telegram() {
    local message="$1"
    curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
        -d "chat_id=$TELEGRAM_CHAT_ID" \
        -d "text=$message" \
        -d "parse_mode=Markdown" >/dev/null 2>&1
    if [ $? -ne 0 ]; then
        echo "⚠️ خطا در ارسال پیام به تلگرام: $message"
    fi
}

# تابع بررسی موفقیت عملیات
check_success() {
    local action="$1"
    local service="$2"
    if [ $? -eq 0 ]; then
        echo "✅ $action"
        send_telegram "✅ $action"
        [ -n "$service" ] && SERVICE_STATUS["$service"]="فعال"
    else
        echo "❌ $action"
        send_telegram "⚠️ خطا در: $action (ادامه فرآیند)"
        [ -n "$service" ] && SERVICE_STATUS["$service"]="خطا"
    fi
}

# =============================================
# شروع فرآیند نصب
# =============================================

send_telegram "🔥 **شروع فرآیند پیکربندی سرور** در $(date)"

# 1. به‌روزرسانی سیستم
echo "🔄 در حال بروزرسانی سیستم..."
sudo apt update && sudo apt upgrade -y
check_success "بروزرسانی سیستم انجام شد"

# 2. ایجاد کاربر جدید
echo "🔄 ایجاد کاربر $NEW_USER..."
sudo adduser --disabled-password --gecos "" "$NEW_USER"
sudo usermod -aG sudo "$NEW_USER"
echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | sudo tee /etc/sudoers.d/"$NEW_USER"
sudo mkdir -p "/home/$NEW_USER/.ssh"
echo "$PUBLIC_KEY" | sudo tee "/home/$NEW_USER/.ssh/authorized_keys"
sudo chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.ssh"
sudo chmod 700 "/home/$NEW_USER/.ssh"
sudo chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
check_success "ایجاد کاربر $NEW_USER"

# تنظیمات SSH
sudo tee /etc/ssh/sshd_config <<EOL
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
sudo systemctl restart sshd
check_success "تنظیمات SSH برای کاربر $NEW_USER"

# =============================================
# نصب Docker و Docker Compose
# =============================================
echo "🔄 نصب Docker و Docker Compose..."
sudo apt install -y apt-transport-https ca-certificates curl software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt update && sudo apt install -y docker-ce docker-ce-cli containerd.io
sudo systemctl enable --now docker
sudo usermod -aG docker "$NEW_USER"
DOCKER_COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
curl -L "https://github.com/docker/compose/releases/download/${DOCKER_COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
sudo chmod +x /usr/local/bin/docker-compose
sudo ln -s /usr/local/bin/docker-compose /usr/bin/docker-compose
check_success "نصب Docker و Docker Compose" "docker"

# =============================================
# نصب و تنظیم Portainer
# =============================================
echo "🔄 نصب Portainer..."
sudo docker volume create portainer_data
sudo docker run -d --name portainer -p "$PORTAINER_PORT:9000" \
    -v /var/run/docker.sock:/var/run/docker.sock \
    -v portainer_data:/data \
    --restart unless-stopped \
    portainer/portainer-ce:latest
check_success "نصب و راه‌اندازی Portainer" "portainer"

# =============================================
# نصب و تنظیم Nginx Proxy Manager
# =============================================
echo "🔄 نصب Nginx Proxy Manager..."
sudo mkdir -p /var/docker/nginx-proxy-manager/{data,letsencrypt}
sudo docker run -d \
    --name nginx-proxy-manager \
    -p 80:80 \
    -p 443:443 \
    -p "$NGINX_PROXY_MANAGER_PORT:81" \
    -v /var/docker/nginx-proxy-manager/data:/data \
    -v /var/docker/nginx-proxy-manager/letsencrypt:/etc/letsencrypt \
    --restart unless-stopped \
    jc21/nginx-proxy-manager:latest
check_success "نصب و راه‌اندازی Nginx Proxy Manager" "nginx-proxy-manager"

# =============================================
# نصب و تنظیم Netdata
# =============================================
echo "🔄 نصب Netdata..."
sudo apt install -y netdata
sudo tee -a /etc/netdata/netdata.conf <<EOL
[web]
    bind to = 0.0.0.0:$NETDATA_PORT
    allow connections from = *
EOL
sudo chown -R netdata:netdata /usr/share/netdata/web
sudo chmod -R 0755 /usr/share/netdata/web
sudo usermod -aG netdata "$NEW_USER"
sudo systemctl enable --now netdata
sudo systemctl restart netdata
check_success "نصب و راه‌اندازی Netdata" "netdata"

# =============================================
# تنظیم فایروال
# =============================================
echo "🔄 تنظیم فایروال..."
sudo apt install -y ufw
sudo ufw default deny incoming
sudo ufw default allow outgoing
for port in "${PORTS_TO_OPEN[@]}"; do
    sudo ufw allow "$port/tcp"
done
sudo ufw --force enable
check_success "تنظیم فایروال"

# =============================================
# نصب و تنظیم CrowdSec
# =============================================
echo "🔄 نصب CrowdSec..."

# نصب پیش‌نیازها
sudo apt install -y curl gnupg iptables || send_telegram "⚠️ خطا در نصب پیش‌نیازهای CrowdSec (ادامه فرآیند)"

# اضافه کردن مخزن
echo "اضافه کردن مخزن CrowdSec..."
sudo bash -c 'curl https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh > /tmp/crowdsec-install.sh'
if sudo bash /tmp/crowdsec-install.sh; then
    sudo rm /tmp/crowdsec-install.sh
    send_telegram "✅ مخزن CrowdSec اضافه شد"
    sudo apt update || send_telegram "⚠️ خطا در بروزرسانی مخازن (ادامه فرآیند)"
    
    # نصب پکیج اصلی
    if sudo apt install -y crowdsec; then
        check_success "نصب پکیج اصلی CrowdSec" "crowdsec"
        # نصب bouncer
        sudo apt install -y crowdsec-firewall-bouncer-iptables
        check_success "نصب bouncer iptables برای CrowdSec" "crowdsec-firewall"
    else
        send_telegram "⚠️ خطا در نصب پکیج crowdsec (ادامه فرآیند)"
    fi
else
    send_telegram "⚠️ خطا در اضافه کردن مخزن CrowdSec (ادامه فرآیند)"
    sudo rm /tmp/crowdsec-install.sh 2>/dev/null || true
fi

# تنظیم فایل کانفیگ
sudo mkdir -p /var/lib/crowdsec/data
sudo tee /etc/crowdsec/config.yaml.local <<EOL
api:
  server:
    listen_uri: 0.0.0.0:$CROWDSEC_DASHBOARD_PORT
    profiles_path: /etc/crowdsec/profiles.yaml
db_config:
  type: sqlite
  db_path: /var/lib/crowdsec/data/crowdsec.db
EOL
sudo chown -R crowdsec:crowdsec /etc/crowdsec /var/lib/crowdsec/data 2>/dev/null || true
sudo chmod -R 755 /var/lib/crowdsec/data

# راه‌اندازی سرویس
if dpkg -l | grep -q crowdsec; then
    sudo systemctl enable --now crowdsec
    sudo systemctl restart crowdsec
    check_success "راه‌اندازی سرویس CrowdSec" "crowdsec"
else
    send_telegram "⚠️ پکیج CrowdSec نصب نشده، راه‌اندازی رد شد (ادامه فرآیند)"
fi

# نصب داشبورد (Metabase) به‌صورت غیرتعاملی
if docker ps >/dev/null 2>&1; then
    echo "نصب داشبورد CrowdSec..."
    sudo cscli dashboard setup --listen 0.0.0.0:$CROWDSEC_DASHBOARD_PORT --force --yes
    if docker ps -a | grep -q metabase; then
        check_success "نصب و راه‌اندازی داشبورد CrowdSec" "crowdsec-dashboard"
    else
        send_telegram "⚠️ خطا در نصب داشبورد CrowdSec، کانتینر ایجاد نشد (ادامه فرآیند)"
    fi
else
    send_telegram "⚠️ Docker کار نمی‌کند، نصب داشبورد CrowdSec رد شد (ادامه فرآیند)"
fi

# باز کردن پورت
sudo ufw allow $CROWDSEC_DASHBOARD_PORT/tcp

# =============================================
# نصب و تنظیم Code-Server
# =============================================
echo "🔄 نصب Code-Server..."
sudo curl -fsSL https://code-server.dev/install.sh | sh
sudo setcap cap_net_bind_service=+ep $(readlink -f $(which node)) 2>/dev/null || true
sudo mkdir -p "/home/$NEW_USER/.config/code-server" "/home/$NEW_USER/.local/share/code-server"
sudo chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.config" "/home/$NEW_USER/.local"
sudo tee "/home/$NEW_USER/.config/code-server/config.yaml" <<EOL
bind-addr: 0.0.0.0:$CODE_SERVER_PORT
auth: password
password: $CODE_SERVER_PASSWORD
cert: false
EOL
sudo tee /etc/systemd/system/code-server.service <<EOL
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
sudo systemctl daemon-reload
sudo systemctl enable --now code-server.service
check_success "نصب و راه‌اندازی Code-Server" "code-server"

# =============================================
# نصب ابزارهای جانبی
# =============================================
echo "🔄 نصب ابزارهای جانبی..."
sudo apt install -y \
    wget curl net-tools iperf3 \
    htop glances tmux \
    rsync vim nano unzip zip \
    build-essential git lftp \
    clamav clamav-daemon rkhunter lynis \
    auditd tcpdump nmap \
    python3-pip python3-venv python3-dev
sudo systemctl enable --now auditd
check_success "نصب ابزارهای جانبی"

# =============================================
# تنظیمات امنیتی نهایی
# =============================================
echo "🔄 اعمال تنظیمات امنیتی..."
sudo tee -a /etc/sysctl.conf <<EOL
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
sudo sysctl -p
check_success "تنظیمات امنیتی اعمال شد"

# =============================================
# گزارش نهایی تلگرام
# =============================================
SERVER_IP=$(curl -s -4 icanhazip.com)
LOCATION=$(curl -s "http://ip-api.com/line/$SERVER_IP?fields=country,city,isp" | tr '\n' ', ' | sed 's/, $//')

# ساخت گزارش وضعیت سرویس‌ها
SERVICES_REPORT=""
for service in "${!SERVICE_STATUS[@]}"; do
    if [ "${SERVICE_STATUS[$service]}" = "فعال" ]; then
        SERVICES_REPORT+="   - **$service**: ✅ فعال\n"
    else
        SERVICES_REPORT+="   - **$service**: ❌ خطا\n"
    fi
done

REPORT="
🚀 **گزارش نهایی پیکربندی سرور**  
⏳ **زمان اجرا:** \`$(date)\`  

---

🔹 **مشخصات سرور:**  
   - **نام سرور:** \`$(hostname)\`  
   - **آدرس IP:** \`$SERVER_IP\`  
   - **موقعیت مکانی:** \`$LOCATION\`  

---

🔹 **وضعیت سرویس‌ها:**  
$SERVICES_REPORT

---

🔹 **لینک‌های دسترسی:**  
   - **Portainer:** [http://$SERVER_IP:$PORTAINER_PORT](http://$SERVER_IP:$PORTAINER_PORT)  
   - **Nginx Proxy Manager:** [http://$SERVER_IP:$NGINX_PROXY_MANAGER_PORT](http://$SERVER_IP:$NGINX_PROXY_MANAGER_PORT)  
   - **Code-Server:** [http://$SERVER_IP:$CODE_SERVER_PORT](http://$SERVER_IP:$CODE_SERVER_PORT)  
   - **Netdata:** [http://$SERVER_IP:$NETDATA_PORT](http://$SERVER_IP:$NETDATA_PORT)  
   - **CrowdSec Dashboard:** [http://$SERVER_IP:$CROWDSEC_DASHBOARD_PORT](http://$SERVER_IP:$CROWDSEC_DASHBOARD_PORT)  

---

🔹 **دسترسی SSH:**  
   - **پورت:** \`$SSH_PORT\`  
   - **کاربر:** \`$NEW_USER\`  
   - **روش احراز هویت:** 🔑 کلید عمومی  
   - **دستور اتصال:** \`ssh -i <کلید_خصوصی> $NEW_USER@$SERVER_IP -p $SSH_PORT\`  

---

🔹 **پورت‌های باز:**  
   - \`${PORTS_TO_OPEN[*]}\`  

🔹 **پورت‌های رزرو‌شده:**  
   - \`${RESERVED_PORTS[*]}\`  

---

📌 **نکات مهم و راهنما:**  
   - **Portainer:** پس از ورود اولیه، رمز عبور را تنظیم کنید.  
   - **Nginx Proxy Manager:** پنل مدیریت وب برای پروکسی.  
   - **Code-Server:** رمز اولیه: \`$CODE_SERVER_PASSWORD\` (توصیه: تغییر دهید).  
   - **Netdata:** مانیتورینگ سیستم در زمان واقعی.  
   - **CrowdSec Dashboard:** نام کاربری: \`admin@crowdsec.net\` | رمز اولیه: \`crowdsec\`  
   - **امنیت:** تمام پورت‌های غیرضروری توسط UFW مسدود شده‌اند.  

✅ **پیکربندی با موفقیت انجام شد!**
"

send_telegram "$REPORT"
echo "✅ گزارش نهایی به تلگرام ارسال شد (چک کنید)"
exit 0
