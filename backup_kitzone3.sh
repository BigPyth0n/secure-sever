#!/bin/bash

# توضیح: اسکریپت بکاپ، تست و آپلود پوشه KitZone3 به گوگل درایو
# تاریخ: 2025-04-02
# نویسنده: با کمک Grok 3 از xAI

# متغیرها
SOURCE_DIR="KitZone3"                    # پوشه مبدا
DATE=$(date +%Y-%m-%d)                   # تاریخ فعلی (مثلاً 2025-04-02)
ARCHIVE_NAME="KitZone3-$DATE.tar.gz"     # اسم فایل فشرده
TEMP_EXTRACT="/tmp/test_extract"         # پوشه موقت برای تست استخراج
TEMP_DOWNLOAD="/tmp/test_download"       # پوشه موقت برای تست دانلود
GDRIVE_PATH="gdrive:Backups"             # مسیر مقصد در گوگل درایو
LOG_FILE="backup_log_$DATE.txt"          # فایل لاگ

# تابع برای لاگ کردن
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# شروع
log "شروع فرآیند بکاپ و آپلود برای $SOURCE_DIR"

# 1. چک کردن پیش‌نیازها
log "چک کردن وجود rclone و فضای دیسک..."
if ! command -v rclone &> /dev/null; then
    log "خطا: rclone نصب نیست! لطفاً نصب کنید: sudo apt install rclone"
    exit 1
fi
FREE_SPACE=$(df -h / | awk 'NR==2 {print $4}')
log "فضای خالی دیسک: $FREE_SPACE"
if [[ $(df -h / | awk 'NR==2 {print $4}' | grep -o '[0-9]\+') -lt 2 ]]; then
    log "خطا: فضای دیسک کافی نیست (حداقل 2 گیگابایت لازم است)"
    exit 1
fi

# 2. فشرده‌سازی
log "فشرده‌سازی $SOURCE_DIR به $ARCHIVE_NAME..."
if tar -czvf "$ARCHIVE_NAME" "$SOURCE_DIR" --verbose 2> tar_error.log; then
    log "فشرده‌سازی با موفقیت انجام شد"
else
    log "خطا در فشرده‌سازی! جزئیات در tar_error.log"
    cat tar_error.log >> "$LOG_FILE"
    exit 1
fi

# 3. بررسی حجم فایل فشرده
log "چک کردن حجم فایل فشرده..."
ARCHIVE_SIZE=$(ls -lh "$ARCHIVE_NAME" | awk '{print $5}')
log "حجم فایل فشرده: $ARCHIVE_SIZE"
SOURCE_SIZE=$(du -sh "$SOURCE_DIR" | awk '{print $1}')
log "حجم پوشه اصلی: $SOURCE_SIZE"

# 4. تست سلامت فایل فشرده
log "تست سلامت فایل فشرده..."
if tar -tzf "$ARCHIVE_NAME" > /dev/null 2>> "$LOG_FILE"; then
    FILE_COUNT=$(tar -tzf "$ARCHIVE_NAME" | wc -l)
    log "فایل سالم است. تعداد فایل‌ها: $FILE_COUNT"
else
    log "خطا: فایل فشرده خراب است!"
    exit 1
fi

# 5. استخراج و مقایسه
log "استخراج فایل فشرده برای تست..."
rm -rf "$TEMP_EXTRACT" && mkdir "$TEMP_EXTRACT"
if tar -xzf "$ARCHIVE_NAME" -C "$TEMP_EXTRACT" 2>> "$LOG_FILE"; then
    log "استخراج با موفقیت انجام شد"
    EXTRACT_SIZE=$(du -sh "$TEMP_EXTRACT/$SOURCE_DIR" | awk '{print $1}')
    log "حجم پوشه استخراج‌شده: $EXTRACT_SIZE"
    log "مقایسه محتویات پوشه اصلی و استخراج‌شده..."
    if diff -r "$SOURCE_DIR" "$TEMP_EXTRACT/$SOURCE_DIR" >> "$LOG_FILE" 2>&1; then
        log "محتویات کاملاً یکسان هستند"
    else
        log "خطا: تفاوت‌هایی بین پوشه‌ها وجود دارد!"
        exit 1
    fi
else
    log "خطا در استخراج فایل فشرده!"
    exit 1
fi

# 6. پاکسازی پوشه موقت
log "پاکسازی پوشه موقت استخراج..."
rm -rf "$TEMP_EXTRACT"
log "پوشه $TEMP_EXTRACT حذف شد"

# 7. آپلود به گوگل درایو
log "آپلود $ARCHIVE_NAME به $GDRIVE_PATH..."
if rclone copy "$ARCHIVE_NAME" "$GDRIVE_PATH" --progress 2>> "$LOG_FILE"; then
    log "آپلود با موفقیت انجام شد"
else
    log "خطا در آپلود به گوگل درایو!"
    exit 1
fi

# 8. لیست فایل‌ها در گوگل درایو
log "چک کردن لیست فایل‌ها در گوگل درایو..."
rclone ls "$GDRIVE_PATH" | tee -a "$LOG_FILE"
log "لیست فایل‌ها دریافت شد"

# 9. تست صحت آپلود
log "دانلود فایل از گوگل درایو برای تست..."
rm -rf "$TEMP_DOWNLOAD" && mkdir "$TEMP_DOWNLOAD"
if rclone copy "$GDRIVE_PATH/$ARCHIVE_NAME" "$TEMP_DOWNLOAD" 2>> "$LOG_FILE"; then
    log "دانلود با موفقیت انجام شد"
    log "استخراج فایل دانلودشده..."
    if tar -xzf "$TEMP_DOWNLOAD/$ARCHIVE_NAME" -C "$TEMP_DOWNLOAD" 2>> "$LOG_FILE"; then
        DOWNLOAD_SIZE=$(du -sh "$TEMP_DOWNLOAD/$SOURCE_DIR" | awk '{print $1}')
        log "حجم پوشه استخراج‌شده از دانلود: $DOWNLOAD_SIZE"
        log "مقایسه محتویات پوشه اصلی و دانلودشده..."
        if diff -r "$SOURCE_DIR" "$TEMP_DOWNLOAD/$SOURCE_DIR" >> "$LOG_FILE" 2>&1; then
            log "فایل آپلودشده کاملاً درست است"
        else
            log "خطا: تفاوت‌هایی در فایل دانلودشده وجود دارد!"
            exit 1
        fi
    else
        log "خطا در استخراج فایل دانلودشده!"
        exit 1
    fi
else
    log "خطا در دانلود از گوگل درایو!"
    exit 1
fi

# 10. پاکسازی نهایی
log "پاکسازی پوشه موقت دانلود..."
rm -rf "$TEMP_DOWNLOAD"
log "پوشه $TEMP_DOWNLOAD حذف شد"

# پایان
log "فرآیند با موفقیت به پایان رسید!"
exit 0
