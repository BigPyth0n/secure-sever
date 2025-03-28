#!/bin/bash
set -e

#==============================================================================================
# تنظیمات اصلی (Config Variables)
#==============================================================================================
TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"
NEW_USER="bigpython"
SSH_PORT="9011"
CODE_SERVER_PORT="1010"
NETDATA_PORT="9001"
WAZUH_DASHBOARD_PORT="5601"
PORTAINER_PORT="9000"
NGINX_PROXY_MANAGER_PORT="81"
CODE_SERVER_PASSWORD="114aa2650b0db5509f36f4fc"
PUBLIC_KEY="ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDdpw/9IFehmdrqt92TwYSAt8tBbt4H9l+yNucOO1z4CCOb/P3X5pH5c7Wspc04n48SDrq/mIYsYvKyym6EDWeKFtocBg+gPjEwOyo07WeSx2zde93C9x0aZLS3paZUxVzqXp1SGzI38u2CluoSeAzk2mKdR3DY1gmSXoPklm1bbzl4VMv1qk1vnvydw3D/RrE2gulfGVfCmgCQ0v3hPqFrs4Bqe125JGSRO7d6MWTI1ph+DN8gARuTvQFN8eFwufiqbMpVZHigIWPyBsb9THTkaCSmIojHZnedSnU5lXikUk+AgUAnfyaf03QwPjrieWjO1edWMBS8ngOGRzWrRssWT8E6GLJ1U0ARPl4XFnUwgYKrMX2mDtggSybn9to0aIxOVM717/EvtdjrwHQ3uGBO+AQ8KoJSumqiboVgA6EjOhk6xrQe3kxBsw/X3EuWD3iW0AJtXo77JIbVIMcPfjUhLNCRy2Ib6MbqNOZ6y4h2PB7ViU8BIqP+p5BgfrqhP0nk2F+YhWU4JbLo6RD9PHMFCCTqG493ameDfPLN+kYn4xSy0BNnBpSgQerHb1O3rrwzjPI7iOyxqO1e4Exi6rcqO6gN7MehfjdeAYCyS3hfILXmWLcEmtQX7RkMlEfAjtWh1Vw/y1GOmc1CJWU45EZxckRxqY37T0OIzR34z0gQJw== bigpyth0n@TradePC
"
#==============================================================================================



#==============================================================================================
# کاربر مخصوص SFTP
#==============================================================================================
SFTP_USER="securftpuser"
SFTP_PASSWORD="uCkdYMqd5F@GGHYSKy9b"
CHROOT_DIR="/home/$SFTP_USER/upload"
#=====================================================================


#=====================================================================
# تنظیمات CrowdSec
#=====================================================================
CROWD_SEC_EMAIL="kitzone.ir@gmail.com"
CROWD_SEC_ENROLLMENT_TOKEN="cm8qh5k6b0007iacrx07s382h"
#=====================================================================


#=====================================================================
# پورت‌های باز و رزرو شده
#=====================================================================
PORTS_TO_OPEN=("80" "443" "$SSH_PORT" "$CODE_SERVER_PORT" "$NETDATA_PORT" "$WAZUH_DASHBOARD_PORT" "$PORTAINER_PORT" "$NGINX_PROXY_MANAGER_PORT")
RESERVED_PORTS=("1020" "1030" "1040" "2060" "3050" "2020" "4040" "3060" "2080")
#=====================================================================



#=====================================================================
# آرایه برای ذخیره وضعیت سرویس‌ها
#=====================================================================
declare -A SERVICE_STATUS
#=====================================================================




#=====================================================================
# توابع کمکی (Helper Functions)
#=====================================================================
install_jq() {
    echo "🔄 بررسی وجود jq در سیستم..."
    
    if command -v jq &>/dev/null; then
        echo "✅ jq از قبل نصب شده است (ورژن: $(jq --version))"
        return 0
    fi
    
    echo "📦 در حال نصب jq..."
    apt update && apt install -y jq
    
    # بررسی نصب موفق
    if command -v jq &>/dev/null; then
        echo "✅ jq با موفقیت نصب شد (ورژن: $(jq --version))"
        return 0
    else
        echo "❌ خطا در نصب jq. ادامه بدون jq..."
        return 1
    fi
}
#=====================================================================



#==============================================================================================
# تابع اسکیپ کاراکترهای MarkdownV2
#==============================================================================================
escape_markdown() {
    local text="$1"
    # اسکیپ کاراکترهای خاص برای MarkdownV2
    text=$(echo "$text" | sed 's/[][_*()~`>#+=|{}.!]/\\&/g')
    echo "$text"
}
#==============================================================================================





#==============================================================================================
# تابع ارسال پیام به تلگرام با قابلیت دیباگ پیشرفته
#==============================================================================================
declare -A SERVICE_STATUS=(
    ["sftp_config"]="فعال"
    ["ufw"]="فعال"
    ["crowdsec"]="فعال"
    ["code-server"]="فعال"
    ["nginx-proxy-manager"]="فعال"
    ["ssh"]="فعال"
    ["docker"]="فعال"
    ["portainer"]="فعال"
    ["netdata"]="فعال"
    ["sftp_user"]="فعال"
)

# تابع ارسال پیام به تلگرام
send_telegram() {
    local message="$1"
    local max_retries=3
    local retry_count=0
    local success=0
    local error_msg=""
    local delay_between_parts=1
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    format_error() {
        local err="$1"
        echo "$err" | sed 's/\\n/\n/g' | sed 's/\\"/"/g' | head -n 1 | cut -c1-200
    }

    if ! command -v curl &>/dev/null; then
        echo "[$timestamp] ❌ خطا: curl نصب نیست. لطفاً curl را نصب کنید."
        return 10
    fi

    echo "[$timestamp] ℹ️ پیام اولیه برای ارسال: '$message'"
    message=$(echo -e "$message")
    message=$(echo "$message" | tr -d '\000-\010\013\014\016-\037' | tr -s ' ')
    echo "[$timestamp] ℹ️ پیام پس از پاکسازی: '$message'"

    if [[ -z "$message" ]]; then
        echo "[$timestamp] ⚠️ پیام خالی است. عملیات ارسال لغو شد."
        return 20
    fi

    local parts=()
    while [ -n "$message" ]; do
        if [ ${#message} -le 4096 ]; then
            parts+=("$message")
            break
        else
            local part="${message:0:4096}"
            local last_newline=$(echo "$part" | awk '{print substr($0,length-200)}' | grep -aob '\n' | tail -1 | cut -d: -f1)
            if [ -n "$last_newline" ]; then  # خط اصلاح‌شده
                part="${message:0:$((4096 - (${#part} - $last_newline)))}"
            fi
            parts+=("$part")
            message="${message:${#part}}"
            echo "[$timestamp] ℹ️ بخش‌بندی پیام: '$part'"
            sleep "$delay_between_parts"
        fi
    done

    local part_count=1
    for part in "${parts[@]}"; do
        retry_count=0
        success=0
        echo "[$timestamp] 🚀 شروع ارسال بخش $part_count از ${#parts[@]}: '$part'"

        while [ $retry_count -lt $max_retries ]; do
            response=$(curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendMessage" \
                -d "chat_id=$TELEGRAM_CHAT_ID" \
                -d "text=$part" \
                -d "parse_mode=HTML" \
                -d "disable_web_page_preview=true" 2>&1)

            if echo "$response" | grep -q '"ok":true'; then
                success=1
                echo "[$timestamp] ✅ بخش $part_count با موفقیت ارسال شد"
                break
            else
                retry_count=$((retry_count + 1))
                error_msg=$(format_error "$response")
                echo "[$timestamp] ⚠️ تلاش $retry_count/$max_retries ناموفق بود. خطا: $error_msg"
                if [ $retry_count -lt $max_retries ]; then
                    sleep 2
                fi
            fi
        done

        if [ $success -eq 0 ]; then
            echo "[$timestamp] ❌ ارسال بخش $part_count پس از $max_retries تلاش شکست خورد: $error_msg"
            return 30
        fi
        part_count=$((part_count + 1))
    done

    echo "[$timestamp] ✅ تمام بخش‌های پیام با موفقیت ارسال شدند (${#parts[@]} بخش)"
    return 0
}
#==============================================================================================










#==============================================================================================
# بررسی موفقیت عملیات و گزارش‌دهی
#==============================================================================================
check_success() {
    local action="$1"
    local service="$2"
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    
    if [ $? -eq 0 ]; then
        echo "[$timestamp] ✅ $action"
        send_telegram "✅ $action"
        [ -n "$service" ] && SERVICE_STATUS["$service"]="فعال"
        return 0
    else
        echo "[$timestamp] ❌ $action"
        send_telegram "⚠️ خطا در: $action"
        [ -n "$service" ] && SERVICE_STATUS["$service"]="خطا"
        return 1
    fi
}
#==============================================================================================







#==============================================================================================
# تابع نصب jq
#==============================================================================================
install_jq || echo "⚠️ ادامه بدون jq..."


#==============================================================================================
# نصب و پیکربندی CrowdSec
#==============================================================================================
install_crowdsec() {
    echo "🔄 نصب CrowdSec با محافظت کامل..."
    
    # نصب CrowdSec
    curl -s https://packagecloud.io/install/repositories/crowdsec/crowdsec/script.deb.sh | bash
    apt install -y crowdsec || { echo "❌ خطا در نصب CrowdSec"; return 1; }
    
    # نصب bouncer برای اعمال بلاک‌ها توی فایروال
    apt install -y crowdsec-firewall-bouncer-nftables || { echo "❌ خطا در نصب bouncer فایروال"; return 1; }
    
    # مجموعه سناریوها برای سرویس‌های مختلف
    local collections=(
        "crowdsecurity/sshd"           # برای SSH و SFTP (پورت 9011)
        "crowdsecurity/nginx"          # برای Nginx Proxy Manager (پورت 80, 443, 81)
        "crowdsecurity/mysql"          # برای MySQL (پورت 3306)
        "crowdsecurity/docker"         # برای Docker
        "crowdsecurity/linux"          # برای امنیت کلی سیستم
        "crowdsecurity/http-cve"       # برای حملات شناخته‌شده HTTP (Streamlit, Code-Server, Portainer, Netdata)
        "crowdsecurity/base-http-scenarios"  # مجموعه پایه HTTP
        "crowdsecurity/port-scan"      # برای تشخیص اسکن پورت
        "crowdsecurity/geoip-enrich"   # برای اطلاعات جغرافیایی
    )
    
    for collection in "${collections[@]}"; do
        echo "   🔄 نصب مجموعه $collection..."
        cscli collections install "$collection" || echo "   ⚠️ خطا در نصب $collection"
    done
    
    # نصب سناریوهای اضافی
    cscli parsers install crowdsecurity/whitelists
    cscli scenarios install crowdsecurity/http-probing  # برای اسکن HTTP
    cscli scenarios install crowdsecurity/ssh-bf        # برای brute-force روی SSH و SFTP
    
    systemctl enable --now crowdsec
    sleep 5
    
    if systemctl is-active --quiet crowdsec && cscli metrics >/dev/null 2>&1; then
        check_success "نصب و راه‌اندازی CrowdSec" "crowdsec"
    else
        echo "❌ خطا در راه‌اندازی CrowdSec"
        SERVICE_STATUS["crowdsec"]="خطا"
        return 1
    fi
}
#==============================================================================================



#==============================================================================================
# اتصال به کنسول CrowdSec
#==============================================================================================
connect_to_console() {
    echo "🔄 اتصال به کنسول CrowdSec..."
    local output=$(cscli console enroll -e "$CROWD_SEC_ENROLLMENT_TOKEN" 2>&1)
    local status=$?
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")

    local REPORT=""
    REPORT+="<b>🔌 گزارش اتصال به کنسول CrowdSec</b>\n"
    REPORT+="<pre>${timestamp}</pre>\n"
    REPORT+="────────────────────\n\n"

    if [ $status -eq 0 ]; then
        SERVICE_STATUS["crowdsec_console"]="✅ متصل"
        REPORT+="<b>🎉 اتصال موفق</b>\n"
        REPORT+="├─ <b>ایمیل</b>: <code>${CROWD_SEC_EMAIL}</code>\n"
        REPORT+="├─ <b>وضعیت</b>: <code>اتصال فعال</code>\n"
        REPORT+="└─ <b>داشبورد</b>: <a href=\"https://app.crowdsec.net/alerts\">مشاهده آلرت‌ها</a>\n"
        send_telegram "$REPORT"
        return 0
    else
        SERVICE_STATUS["crowdsec_console"]="❌ خطا"
        REPORT+="<b>⚠️ خطا در اتصال</b>\n"
        REPORT+="├─ <b>ایمیل</b>: <code>${CROWD_SEC_EMAIL}</code>\n"
        REPORT+="└─ <b>خطا</b>: <code>${output:0:200}</code>\n"
        send_telegram "$REPORT"
        return 1
    fi
}
#==============================================================================================





#==============================================================================================
# پیکربندی کاربر SFTP (نسخه اصلاح شده فقط برای افزودن تنظیمات رمزنگاری)
#==============================================================================================
configure_sftp() {
    echo "🔄 ایجاد و پیکربندی کاربر SFTP..."
    
    if id "$SFTP_USER" &>/dev/null; then
        echo "⚠️ کاربر $SFTP_USER از قبل وجود دارد"
        send_telegram "⚠️ کاربر SFTP از قبل وجود دارد"
    else
        useradd -m -s /usr/sbin/nologin "$SFTP_USER" && \
        echo "$SFTP_USER:$SFTP_PASSWORD" | chpasswd && \
        mkdir -p "/home/$SFTP_USER/.ssh" && \
        echo "$PUBLIC_KEY" > "/home/$SFTP_USER/.ssh/authorized_keys" && \
        chown -R "$SFTP_USER:$SFTP_USER" "/home/$SFTP_USER/.ssh" && \
        chmod 700 "/home/$SFTP_USER/.ssh" && \
        chmod 600 "/home/$SFTP_USER/.ssh/authorized_keys"
        
        check_success "ایجاد کاربر SFTP" "sftp_user" || return 1
    fi

    echo "🔒 تنظیمات امنیتی SFTP..."
    if ! grep -q "Subsystem sftp" /etc/ssh/sshd_config; then
        cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
        
        # تنظیمات جهانی SSH
        cat <<EOL > /etc/ssh/sshd_config
# تنظیمات جهانی
Subsystem sftp internal-sftp
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
AuthenticationMethods publickey
AllowUsers $NEW_USER $SFTP_USER
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519
HostKeyAlgorithms +ssh-rsa,ssh-ed25519

# تنظیمات خاص کاربر SFTP
Match User $SFTP_USER
    ForceCommand internal-sftp -d /upload
    PasswordAuthentication yes
    PubkeyAuthentication yes
    AuthenticationMethods publickey,password
    ChrootDirectory %h
    PermitTunnel no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
EOL

        chown root:root /home/$SFTP_USER
        chmod 755 /home/$SFTP_USER
        mkdir -p /home/$SFTP_USER/upload
        chown $SFTP_USER:$SFTP_USER /home/$SFTP_USER/upload
        
        # تست صحت پیکربندی قبل از restart
        if sshd -t; then
            systemctl restart sshd
            check_success "تنظیمات امنیتی SFTP" "sftp_config"
        else
            echo "❌ خطا در پیکربندی sshd_config. لطفاً فایل را بررسی کنید."
            send_telegram "❌ خطا در پیکربندی sshd_config"
            cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
            return 1
        fi
    else
        echo "✅ تنظیمات SFTP از قبل اعمال شده است"
        # فقط اضافه کردن تنظیمات رمزنگاری اگه وجود نداشت
        if ! grep -q "PubkeyAcceptedAlgorithms" /etc/ssh/sshd_config; then
            echo "PubkeyAcceptedAlgorithms +ssh-rsa,ssh-ed25519" >> /etc/ssh/sshd_config
            echo "HostKeyAlgorithms +ssh-rsa,ssh-ed25519" >> /etc/ssh/sshd_config
            systemctl restart sshd
        fi
    fi
}
#==============================================================================================





#==============================================================================================
# ریستارت سرویس‌ها و کانتینرها
#==============================================================================================
restart_services() {
    echo "🔄 ریستارت سرویس‌ها و کانتینرها..."

    local system_services=("docker" "code-server@$NEW_USER.service" "netdata" "crowdsec" "ssh")
    local docker_containers=("portainer" "nginx-proxy-manager")
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local RESTART_REPORT=""

    # سرصفحه گزارش
    RESTART_REPORT+="<b>🔄 گزارش ریستارت سرویس‌ها</b>\n"
    RESTART_REPORT+="<pre>${timestamp}</pre>\n"
    RESTART_REPORT+="────────────────────\n\n"

    # سرویس‌های سیستم
    RESTART_REPORT+="<b>🛠️ سرویس‌های سیستم</b>\n"
    for service in "${system_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            systemctl restart "$service" &>/dev/null
            if [ $? -eq 0 ]; then
                RESTART_REPORT+="├─ <b>${service}</b>: <code>✅ ریستارت موفق</code>\n"
            else
                RESTART_REPORT+="├─ <b>${service}</b>: <code>❌ خطا در ریستارت</code>\n"
            fi
        else
            RESTART_REPORT+="├─ <b>${service}</b>: <code>⚠️ غیرفعال</code>\n"
        fi
    done
    RESTART_REPORT="${RESTART_REPORT%├─*}└─${RESTART_REPORT##*├─}"  # تبدیل آخرین ├─ به └─

    # کانتینرهای Docker
    RESTART_REPORT+="\n<b>🐳 کانتینرهای Docker</b>\n"
    for container in "${docker_containers[@]}"; do
        if docker ps -a --format '{{.Names}}' | grep -q "$container"; then
            docker restart "$container" &>/dev/null
            if [ $? -eq 0 ]; then
                RESTART_REPORT+="├─ <b>${container}</b>: <code>✅ ریستارت موفق</code>\n"
            else
                RESTART_REPORT+="├─ <b>${container}</b>: <code>❌ خطا در ریستارت</code>\n"
            fi
        else
            RESTART_REPORT+="├─ <b>${container}</b>: <code>⚠️ یافت نشد</code>\n"
        fi
    done
    RESTART_REPORT="${RESTART_REPORT%├─*}└─${RESTART_REPORT##*├─}"  # تبدیل آخرین ├─ به └─

    # ارسال گزارش
    send_telegram "$RESTART_REPORT"
    echo "✅ گزارش ریستارت سرویس‌ها ارسال شد"
}
#==============================================================================================





#==============================================================================================
# تولید گزارش CrowdSec
#==============================================================================================
generate_crowdsec_report() {
    local report="<b>🛡️ گزارش امنیتی CrowdSec</b>\n"
    report+="<pre>$(date +"%Y-%m-%d %H:%M:%S")</pre>\n"
    report+="────────────────────\n\n"

    report+="<b>📊 آمار تحلیل لاگ‌ها:</b>\n"
    local log_stats=$(sudo cscli metrics --no-color 2>/dev/null | awk -F'│' '
        /file:\/var\/log/ {
            gsub(/^[ \t]+|[ \t]+$/, "", $1);
            gsub(/^[ \t]+|[ \t]+$/, "", $2);
            gsub(/^[ \t]+|[ \t]+$/, "", $3);
            if ($2 ~ /^[0-9]+$/) {
                printf("• %s: %s خطوط پردازش‌شده, %s پارس‌شده\n", $1, $2, $3);
            }
        }')
    report+="${log_stats:-• اطلاعاتی یافت نشد}\n\n"

    report+="<b>🚨 تصمیمات امنیتی اخیر:</b>\n"
    local decisions=$(sudo cscli decisions list --no-color -o json 2>/dev/null | jq -r '
        [group_by(.reason)[] | {
            reason: .[0].reason,
            count: length,
            ips: (map(.value) | unique | join(", "))
        }] | sort_by(.count) | reverse[] | 
        "• " + .reason + " (" + (.count|tostring) + " مورد): " + .ips' 2>/dev/null)
    report+="${decisions:-• موردی یافت نشد}\n\n"

    report+="<b>🔌 وضعیت LAPI:</b>\n"
    local lapi_status=$(sudo cscli lapi status 2>/dev/null | awk '
        /URL:/ { printf("• آدرس: %s\n", $2) }
        /Login:/ { printf("• ورود: %s\n", $2) }
        /Credentials:/ { printf("• اعتبار: %s\n", $2) }
    ')
    report+="${lapi_status:-• اطلاعات در دسترس نیست}\n"

    echo -e "$report"
}
#==============================================================================================







#==============================================================================================
# اعمال تنظیمات امنیتی سیستم
#==============================================================================================
configure_security() {
    echo "🔄 اعمال تنظیمات امنیتی..."
    rm -f /etc/sysctl.d/99-server-security.conf
    cat <<EOL > /etc/sysctl.d/99-server-security.conf
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
    
    sysctl -p /etc/sysctl.d/99-server-security.conf
    check_success "اعمال تنظیمات امنیتی"
}
#==============================================================================================




#==============================================================================================
# تولید گزارش نهایی
#==============================================================================================
generate_final_report() {
    echo "🔄 در حال آماده‌سازی گزارش نهایی..."

    local SERVER_IP=$(curl -4 -s ifconfig.me || echo "نامشخص")
    local LOCATION=$(curl -s "http://ip-api.com/json/$SERVER_IP?fields=country,city,isp" 2>/dev/null | \
                    jq -r '[.country, .city, .isp] | join(" | ")' 2>/dev/null || echo "نامشخص")
    local HOSTNAME=$(hostname)
    local UPTIME=$(uptime -p | sed 's/up //')
    local LOAD_AVG=$(uptime | awk -F'load average: ' '{print $2}')
    local DISK_USAGE=$(df -h / | awk 'NR==2 {print $5 " از " $2 " (" $3 "/" $4 ")"}')
    local MEMORY_USAGE=$(free -m | awk 'NR==2 {print $3 "MB از " $2 "MB (" int($3/$2*100) "%)"}')

    local SECURITY_REPORT=$(generate_crowdsec_report)

    local SERVICES_INFO=""
    declare -A SERVICE_PORTS=(
        ["portainer"]="9000"
        ["nginx-proxy-manager"]="81"
        ["code-server"]="1010"
        ["netdata"]="9001"
    )
    local SELECTED_SERVICES=("portainer" "nginx-proxy-manager" "code-server" "netdata")

    for service in "${SELECTED_SERVICES[@]}"; do
        if [ "${SERVICE_STATUS[$service]}" == "فعال" ]; then
            local port=${SERVICE_PORTS[$service]}
            SERVICES_INFO+="• <a href=\"http://${SERVER_IP}:${port}\"><b>${service^}</b></a>: ${port}\n"
        fi
    done

    local SFTP_INFO=""
    SFTP_INFO+="<b>🔒 اطلاعات اتصال SFTP</b>\n"
    SFTP_INFO+="├─ <b>آی‌پی</b>: <code>${SERVER_IP}</code>\n"
    SFTP_INFO+="├─ <b>پورت</b>: <code>${SSH_PORT}</code>\n"
    SFTP_INFO+="├─ <b>کاربر</b>: <code>${SFTP_USER}</code>\n"
    SFTP_INFO+="├─ <b>رمز عبور</b>: <code>${SFTP_PASSWORD}</code>\n"
    SFTP_INFO+="└─ <b>کلید عمومی</b>: <code>${PUBLIC_KEY}</code>\n"

    local FINAL_REPORT=""
    FINAL_REPORT+="<b>📡 گزارش جامع سرور</b>\n"
    FINAL_REPORT+="<pre>$(date +"%Y-%m-%d %H:%M:%S")</pre>\n"
    FINAL_REPORT+="────────────────────\n\n"

    FINAL_REPORT+="<b>🖥️ اطلاعات سرور</b>\n"
    FINAL_REPORT+="├─ <b>آی‌پی</b>: <code>${SERVER_IP}</code>\n"
    FINAL_REPORT+="├─ <b>موقعیت</b>: ${LOCATION}\n"
    FINAL_REPORT+="├─ <b>میزبان</b>: <code>${HOSTNAME}</code>\n"
    FINAL_REPORT+="├─ <b>آپتایم</b>: ${UPTIME}\n"
    FINAL_REPORT+="├─ <b>بار سیستم</b>: ${LOAD_AVG}\n"
    FINAL_REPORT+="├─ <b>فضای دیسک</b>: ${DISK_USAGE}\n"
    FINAL_REPORT+="└─ <b>حافظه</b>: ${MEMORY_USAGE}\n\n"

    FINAL_REPORT+="<b>🔑 دسترسی‌ها</b>\n"
    FINAL_REPORT+="├─ <b>کاربر اصلی</b>: <code>${NEW_USER}</code>\n"
    FINAL_REPORT+="├─ <b>پورت SSH</b>: <code>${SSH_PORT}</code>\n"
    FINAL_REPORT+="└─ <b>کاربر SFTP</b>: <code>${SFTP_USER}</code>\n\n"

    FINAL_REPORT+="<b>🛠️ سرویس‌های فعال</b>\n"
    FINAL_REPORT+="${SERVICES_INFO:-└─ هیچ سرویس فعالی یافت نشد}\n\n"

    FINAL_REPORT+="${SECURITY_REPORT}\n"

    FINAL_REPORT+="<b>📌 نکات امنیتی</b>\n"
    FINAL_REPORT+="├─ <b>فایروال</b>: فعال و پیکربندی‌شده\n"
    FINAL_REPORT+="├─ <b>آخرین بروزرسانی</b>: $(date -d "@$(stat -c %Y /var/lib/apt/periodic/update-success-stamp 2>/dev/null)" +"%Y-%m-%d %H:%M" 2>/dev/null || echo "نامشخص")\n"
    FINAL_REPORT+="└─ <b>کنسول CrowdSec</b>: <a href=\"https://app.crowdsec.net/\">مشاهده</a>\n\n"

    FINAL_REPORT+="${SFTP_INFO}"

    send_telegram "$FINAL_REPORT"
    echo "✅ گزارش نهایی با موفقیت ارسال شد"
}
#==============================================================================================




#==============================================================================================
# نصب و بررسی jq (JQ Installer)
#==============================================================================================
install_jq() {
    echo "🔄 بررسی وجود jq در سیستم..."
    
    if command -v jq &>/dev/null; then
        echo "✅ jq از قبل نصب شده است (ورژن: $(jq --version))"
        return 0
    fi
    
    echo "📦 در حال نصب jq..."
    
    # تشخیص توزیع لینوکس برای نصب صحیح
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        case $ID in
            debian|ubuntu)
                apt update && apt install -y jq
                ;;
            centos|rhel|fedora)
                yum install -y jq
                ;;
            alpine)
                apk add jq
                ;;
            *)
                # نصب از سورس برای توزیع‌های ناشناخته
                curl -L -o /usr/local/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
                chmod +x /usr/local/bin/jq
                ;;
        esac
    else
        # روش fallback اگر /etc/os-release وجود نداشت
        curl -L -o /usr/local/bin/jq https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64
        chmod +x /usr/local/bin/jq
    fi
    
    # بررسی نصب موفق
    if command -v jq &>/dev/null; then
        echo "✅ jq با موفقیت نصب شد (ورژن: $(jq --version))"
        return 0
    else
        echo "❌ خطا در نصب jq"
        return 1
    fi
}
#==============================================================================================










#××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××
# ریستارت سرویس‌ها و کانتینرها
#××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××
restart_services() {
    echo "🔄 ریستارت سرویس‌ها و کانتینرها..."

    local system_services=("docker" "code-server@$NEW_USER.service" "netdata" "crowdsec" "ssh")
    local docker_containers=("portainer" "nginx-proxy-manager")
    local timestamp=$(date +"%Y-%m-%d %H:%M:%S")
    local RESTART_REPORT=""

    # سرصفحه گزارش
    RESTART_REPORT+="<b>🔄 گزارش ریستارت سرویس‌ها</b>\n"
    RESTART_REPORT+="<pre>${timestamp}</pre>\n"
    RESTART_REPORT+="────────────────────\n\n"

    # سرویس‌های سیستم
    RESTART_REPORT+="<b>🛠️ سرویس‌های سیستم</b>\n"
    for service in "${system_services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            systemctl restart "$service" &>/dev/null
            if [ $? -eq 0 ]; then
                RESTART_REPORT+="├─ <b>${service}</b>: <code>✅ ریستارت موفق</code>\n"
            else
                RESTART_REPORT+="├─ <b>${service}</b>: <code>❌ خطا در ریستارت</code>\n"
            fi
        else
            RESTART_REPORT+="├─ <b>${service}</b>: <code>⚠️ غیرفعال</code>\n"
        fi
    done
    RESTART_REPORT="${RESTART_REPORT%├─*}└─${RESTART_REPORT##*├─}"  # تبدیل آخرین ├─ به └─

    # کانتینرهای Docker
    RESTART_REPORT+="\n<b>🐳 کانتینرهای Docker</b>\n"
    for container in "${docker_containers[@]}"; do
        if docker ps -a --format '{{.Names}}' | grep -q "$container"; then
            docker restart "$container" &>/dev/null
            if [ $? -eq 0 ]; then
                RESTART_REPORT+="├─ <b>${container}</b>: <code>✅ ریستارت موفق</code>\n"
            else
                RESTART_REPORT+="├─ <b>${container}</b>: <code>❌ خطا در ریستارت</code>\n"
            fi
        else
            RESTART_REPORT+="├─ <b>${container}</b>: <code>⚠️ یافت نشد</code>\n"
        fi
    done
    RESTART_REPORT="${RESTART_REPORT%├─*}└─${RESTART_REPORT##*├─}"  # تبدیل آخرین ├─ به └─

    # ارسال گزارش
    send_telegram "$RESTART_REPORT"
    echo "✅ گزارش ریستارت سرویس‌ها ارسال شد"
}
#××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××××




                             
#==============================================================================================
#=====================================================================
#==============================================================================================
                                # تابع اصلی (Main Function)
#==============================================================================================
#=====================================================================
#==============================================================================================
main() {
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # گزارش شروع
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    local START_REPORT="
     🔥 <b>شروع فرآیند پیکربندی سرور</b>
     ⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯⎯
     🕒 <b>زمان:</b> $(date +"%Y-%m-%d %H:%M:%S")
     🌍 <b>IP:</b> <code>$(curl -s ifconfig.me || echo "نامشخص")</code>
     📌 <b>موقعیت:</b> $(curl -s "http://ip-api.com/json/$(curl -s ifconfig.me)?fields=country,city,isp" | jq -r '.country + "، " + .city + " (" + .isp + ")"' 2>/dev/null || echo "نامشخص")
     🌍 <b>میزبان:</b> <code>$(hostname)</code>
     🔄 <b>کاربر اصلی:</b> <code>$NEW_USER</code>
     🔒 <b>پورت SSH:</b> <code>$SSH_PORT</code>
     "
    send_telegram "$START_REPORT"

    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # 1. به‌روزرسانی سیستم
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    echo "🔄 در حال بروزرسانی سیستم..."
    apt update && apt upgrade -y
    check_success "بروزرسانی سیستم انجام شد" || { echo "❌ خطا در بروزرسانی سیستم، ادامه می‌دهیم..."; }

    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # 2. نصب jq (برای پردازش JSON)
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    echo "🔄 نصب jq برای پردازش JSON..."
    if ! command -v jq &>/dev/null; then
        apt install -y jq || { echo "❌ خطا در نصب jq، ادامه بدون jq..."; }
    else
        echo "✅ jq از قبل نصب شده است (ورژن: $(jq --version))"
    fi

    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # 3. تنظیمات کاربر bigpython
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    echo "🔄 تنظیمات کاربر $NEW_USER..."
    if id "$NEW_USER" &>/dev/null; then
        echo "⚠️ کاربر $NEW_USER از قبل وجود دارد، به‌روزرسانی کلید عمومی..."
    else
        echo "🔄 ایجاد کاربر $NEW_USER..."
        adduser --disabled-password --gecos "" "$NEW_USER" && \
        usermod -aG sudo "$NEW_USER" && \
        echo "$NEW_USER ALL=(ALL) NOPASSWD: ALL" | tee /etc/sudoers.d/"$NEW_USER" || { echo "❌ خطا در ایجاد کاربر $NEW_USER"; return 1; }
    fi

    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # 4. اعمال کلید عمومی جدید برای SSH
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    mkdir -p "/home/$NEW_USER/.ssh"
    echo "$PUBLIC_KEY" > "/home/$NEW_USER/.ssh/authorized_keys"
    chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.ssh"
    chmod 700 "/home/$NEW_USER/.ssh"
    chmod 600 "/home/$NEW_USER/.ssh/authorized_keys"
    check_success "تنظیمات کاربر $NEW_USER" || { echo "❌ خطا در تنظیمات کاربر $NEW_USER، ادامه می‌دهیم..."; }

    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    # 5. تنظیمات SSH
    #!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
    echo "🔄 تنظیمات امنیتی SSH..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.bak
    cat <<EOL > /etc/ssh/sshd_config
    
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
# تنظیمات جهانی SSH
#!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
Port $SSH_PORT
PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
AuthenticationMethods publickey
AllowUsers $NEW_USER $SFTP_USER
MaxAuthTries 3
LoginGraceTime 30
ClientAliveInterval 300
ClientAliveCountMax 2
X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
EOL
    # تست صحت پیکربندی و ریستارت سرویس SSH
    if sshd -t; then
        systemctl restart sshd
        check_success "تنظیمات SSH" "ssh"
    else
        echo "❌ خطا در پیکربندی sshd_config، بازگردانی نسخه قبلی..."
        cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config
        systemctl restart sshd
        check_success "بازگردانی تنظیمات SSH" "ssh" || { echo "❌ خطا در بازگردانی SSH، ادامه می‌دهیم..."; }
    fi

    # 5. پیکربندی SFTP
    configure_sftp

    # 6. نصب Docker
    echo "🔄 نصب Docker و Docker Compose..."
    if ! command -v docker &>/dev/null; then
        apt install -y apt-transport-https ca-certificates curl software-properties-common && \
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg | apt-key add - && \
        add-apt-repository -y "deb [arch=amd64] https://download.docker.com/linux/ubuntu jammy stable" && \
        apt update && apt install -y docker-ce docker-ce-cli containerd.io && \
        systemctl enable --now docker && \
        usermod -aG docker "$NEW_USER" && \
        curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose && \
        chmod +x /usr/local/bin/docker-compose
        check_success "نصب Docker و Docker Compose" "docker"
    else
        echo "✅ Docker از قبل نصب شده است"
        SERVICE_STATUS["docker"]="فعال"
    fi

    # 7. نصب Portainer
    echo "🔄 نصب Portainer..."
    if ! docker ps -a --format '{{.Names}}' | grep -q 'portainer'; then
        docker volume create portainer_data && \
        docker run -d --name portainer -p "$PORTAINER_PORT:9000" \
            -v /var/run/docker.sock:/var/run/docker.sock \
            -v portainer_data:/data \
            --restart unless-stopped \
            portainer/portainer-ce:latest
        check_success "نصب Portainer" "portainer"
    else
        echo "✅ Portainer از قبل نصب شده است"
        SERVICE_STATUS["portainer"]="فعال"
    fi

    # 8. نصب Nginx Proxy Manager
    echo "🔄 نصب Nginx Proxy Manager..."
    if ! docker ps -a --format '{{.Names}}' | grep -q 'nginx-proxy-manager'; then
        mkdir -p /var/docker/nginx-proxy-manager/{data,letsencrypt} && \
        docker run -d \
            --name nginx-proxy-manager \
            -p 80:80 \
            -p 443:443 \
            -p "$NGINX_PROXY_MANAGER_PORT:81" \
            -v /var/docker/nginx-proxy-manager/data:/data \
            -v /var/docker/nginx-proxy-manager/letsencrypt:/etc/letsencrypt \
            --restart unless-stopped \
            jc21/nginx-proxy-manager:latest
        check_success "نصب Nginx Proxy Manager" "nginx-proxy-manager"
    else
        echo "✅ Nginx Proxy Manager از قبل نصب شده است"
        SERVICE_STATUS["nginx-proxy-manager"]="فعال"
    fi

    # 9. نصب Netdata
    echo "🔄 نصب Netdata..."
    if ! systemctl is-active --quiet netdata; then
        apt purge -y netdata netdata-core netdata-web netdata-plugins-bash && \
        rm -rf /etc/netdata /usr/share/netdata /var/lib/netdata && \
        wget -O /tmp/netdata-kickstart.sh https://my-netdata.io/kickstart.sh && \
        bash /tmp/netdata-kickstart.sh --stable-channel --disable-telemetry && \
        tee /etc/netdata/netdata.conf <<EOL
[global]
    run as user = netdata
[web]
    bind to = 0.0.0.0:$NETDATA_PORT
    allow connections from = *
    web files owner = netdata
    web files group = netdata
    mode = static-threaded
EOL
        chown -R netdata:netdata /usr/share/netdata/web && \
        chmod -R 0755 /usr/share/netdata/web && \
        systemctl restart netdata
        check_success "نصب Netdata" "netdata"
    else
        echo "✅ Netdata از قبل نصب شده است"
        SERVICE_STATUS["netdata"]="فعال"
    fi

    # 10. نصب CrowdSec
    install_crowdsec

    # 11. تنظیم فایروال
    echo "🔄 تنظیم فایروال..."
    if ! command -v ufw &>/dev/null; then
        apt install -y ufw
    fi
    ufw --force reset
    ufw default deny incoming
    ufw default allow outgoing
    for port in "${PORTS_TO_OPEN[@]}"; do
        ufw allow "$port/tcp"
        echo "   🔓 پورت $port/tcp باز شد"
    done
    
    for port in "${RESERVED_PORTS[@]}"; do
    ufw allow "$port/tcp"
    echo "   🔓 پورت رزرو $port/tcp باز شد"
    done
    
    ufw --force enable
    check_success "تنظیم فایروال" "ufw"

    # 12. نصب Code-Server
    echo "🔄 نصب Code-Server..."
    if ! command -v code-server &>/dev/null; then
        curl -fsSL https://code-server.dev/install.sh | sh && \
        setcap cap_net_bind_service=+ep /usr/lib/code-server/lib/node && \
        systemctl enable --now code-server@"$NEW_USER" && \
        mkdir -p "/home/$NEW_USER/.config/code-server" && \
        cat <<EOL > "/home/$NEW_USER/.config/code-server/config.yaml"
bind-addr: 0.0.0.0:$CODE_SERVER_PORT
auth: password
password: $CODE_SERVER_PASSWORD
cert: false
EOL
        chown -R "$NEW_USER":"$NEW_USER" "/home/$NEW_USER/.config" && \
        systemctl restart code-server@"$NEW_USER"
        
        sleep 5
        if netstat -tuln | grep -q "$CODE_SERVER_PORT"; then
            check_success "نصب Code-Server" "code-server"
        else
            echo "❌ Code-Server روی پورت $CODE_SERVER_PORT اجرا نشد"
            SERVICE_STATUS["code-server"]="خطا"
        fi
    else
        echo "✅ Code-Server از قبل نصب شده است"
        SERVICE_STATUS["code-server"]="فعال"
    fi

    # 13. نصب ابزارهای جانبی
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
    check_success "نصب ابزارهای جانبی"

    # 14. تنظیمات امنیتی سیستم
    configure_security

    # 15. اتصال به کنسول CrowdSec
    connect_to_console

    # 16. ریستارت سرویس‌ها
    restart_services

    # 17. تولید گزارش نهایی
    generate_final_report

    echo "🎉 پیکربندی سرور با موفقیت تکمیل شد!"
}
#=====================================================================





#=====================================================================
# اجرای تابع اصلی
#=====================================================================
main "$@"
