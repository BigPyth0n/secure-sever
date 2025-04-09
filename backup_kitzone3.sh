#!/bin/bash

# توضیح: اسکریپت بکاپ، تست و آپلود پوشه KitZone3 به گوگل درایو + ارسال لاگ به تلگرام
# تاریخ: 2025-04-09
# نویسنده: بهروز

# ================== متغیرها ==================
SOURCE_DIR="/home/bigpython/KitZone3"
DATE=$(date +%Y-%m-%d)
ARCHIVE_NAME="KitZone3-$DATE.tar.gz"
TEMP_EXTRACT="/tmp/test_extract"
TEMP_DOWNLOAD="/tmp/test_download"
GDRIVE_PATH="gdrive:Backups"
LOG_FILE="backup_log_$DATE.txt"

TELEGRAM_BOT_TOKEN="5054947489:AAFSNuI5JP0MhywlkZQIlePqubUpfVFhH9Q"
TELEGRAM_CHAT_ID="59941862"

# تابع لاگ‌نویسی
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# ================== شروع ==================
log "شروع فرآیند بکاپ و آپلود برای $SOURCE_DIR"

# چک وجود پوشه مبدا
if [ ! -d "$SOURCE_DIR" ]; then
    log "خطا: پوشه $SOURCE_DIR وجود ندارد!"
    exit 1
fi

# چک پیش‌نیازها
log "چک کردن وجود rclone و فضای دیسک..."
if ! command -v rclone &> /dev/null; then
    log "خطا: rclone نصب نیست! لطفاً نصب کنید: sudo apt install rclone"
    exit 1
fi

FREE_KB=$(df --output=avail / | tail -1)
if (( FREE_KB < 2*1024*1024 )); then
    log "خطا: حداقل 2 گیگابایت فضای خالی نیاز است!"
    exit 1
fi
log "فضای دیسک کافی است."

# ================== فشرده‌سازی ==================
log "در حال فشرده‌سازی $SOURCE_DIR به $ARCHIVE_NAME..."
if tar -czvf "$ARCHIVE_NAME" "$SOURCE_DIR" --verbose 2> tar_error.log; then
    log "✅ فشرده‌سازی با موفقیت انجام شد."
else
    log "❌ خطا در فشرده‌سازی. جزئیات در tar_error.log"
    cat tar_error.log >> "$LOG_FILE"
    exit 1
fi

# بررسی حجم فایل
ARCHIVE_SIZE=$(ls -lh "$ARCHIVE_NAME" | awk '{print $5}')
SOURCE_SIZE=$(du -sh "$SOURCE_DIR" | awk '{print $1}')
log "📦 حجم فایل فشرده: $ARCHIVE_SIZE | حجم پوشه اصلی: $SOURCE_SIZE"

# ================== تست سالم بودن فایل فشرده ==================
log "تست سلامت فایل فشرده..."
if tar -tzf "$ARCHIVE_NAME" > /dev/null 2>> "$LOG_FILE"; then
    FILE_COUNT=$(tar -tzf "$ARCHIVE_NAME" | wc -l)
    log "✅ فایل سالم است. تعداد فایل‌ها: $FILE_COUNT"
else
    log "❌ فایل فشرده خراب است!"
    exit 1
fi

# ================== استخراج و مقایسه ==================
log "استخراج فایل فشرده برای تست..."
rm -rf "$TEMP_EXTRACT" && mkdir "$TEMP_EXTRACT"
if tar -xzf "$ARCHIVE_NAME" -C "$TEMP_EXTRACT" 2>> "$LOG_FILE"; then
    EXTRACT_SIZE=$(du -sh "$TEMP_EXTRACT/$SOURCE_DIR" | awk '{print $1}')
    log "📁 استخراج موفق. حجم: $EXTRACT_SIZE"
    log "مقایسه محتویات اصلی و استخراج‌شده..."
    if diff -r "$SOURCE_DIR" "$TEMP_EXTRACT/$SOURCE_DIR" >> "$LOG_FILE" 2>&1; then
        log "✅ محتویات یکسان هستند."
    else
        log "❌ تفاوت‌هایی وجود دارد!"
        exit 1
    fi
else
    log "❌ خطا در استخراج فایل فشرده!"
    exit 1
fi

rm -rf "$TEMP_EXTRACT"
log "📂 پوشه موقت استخراج حذف شد."

# ================== آپلود به گوگل درایو ==================
log "آپلود به گوگل درایو..."
if rclone copy "$ARCHIVE_NAME" "$GDRIVE_PATH" --progress 2>> "$LOG_FILE"; then
    log "✅ آپلود موفقیت‌آمیز بود."
else
    log "❌ خطا در آپلود!"
    exit 1
fi

# بررسی فایل در درایو
log "بررسی وجود فایل در گوگل درایو..."
if rclone ls "$GDRIVE_PATH" | grep -q "$ARCHIVE_NAME"; then
    log "✅ فایل در گوگل درایو یافت شد."
else
    log "❌ فایل در درایو پیدا نشد!"
    exit 1
fi

# ================== دانلود برای تست ==================
log "دانلود فایل از گوگل درایو برای تست صحت..."
rm -rf "$TEMP_DOWNLOAD" && mkdir "$TEMP_DOWNLOAD"
if rclone copy "$GDRIVE_PATH/$ARCHIVE_NAME" "$TEMP_DOWNLOAD" 2>> "$LOG_FILE"; then
    log "✅ دانلود موفق."
    if tar -xzf "$TEMP_DOWNLOAD/$ARCHIVE_NAME" -C "$TEMP_DOWNLOAD" 2>> "$LOG_FILE"; then
        DOWNLOAD_SIZE=$(du -sh "$TEMP_DOWNLOAD/$SOURCE_DIR" | awk '{print $1}')
        log "📁 حجم استخراج‌شده از دانلود: $DOWNLOAD_SIZE"
        if diff -r "$SOURCE_DIR" "$TEMP_DOWNLOAD/$SOURCE_DIR" >> "$LOG_FILE" 2>&1; then
            log "✅ فایل آپلودشده کاملاً سالم است."
        else
            log "❌ تفاوت در فایل آپلودشده!"
            exit 1
        fi
    else
        log "❌ خطا در استخراج فایل دانلودی!"
        exit 1
    fi
else
    log "❌ خطا در دانلود فایل از گوگل درایو!"
    exit 1
fi

rm -rf "$TEMP_DOWNLOAD"
log "📂 پوشه موقت دانلود حذف شد."

# ================== پاکسازی و ارسال گزارش ==================
rm -f "$ARCHIVE_NAME"
log "🧹 فایل بکاپ محلی حذف شد."

log "✅ بکاپ‌گیری با موفقیت کامل انجام شد!"

# ================== ارسال به تلگرام ==================
log "📤 ارسال لاگ به تلگرام..."
curl -s -X POST "https://api.telegram.org/bot$TELEGRAM_BOT_TOKEN/sendDocument" \
     -F chat_id="$TELEGRAM_CHAT_ID" \
     -F document=@"$LOG_FILE" \
     -F caption="✅ گزارش بکاپ KitZone3 - تاریخ $DATE"

exit 0
