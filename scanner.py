import hashlib
import os
import zipfile
import mimetypes
import datetime

# 💥 ฐานข้อมูลมัลแวร์แบบละเอียด
known_malware = {
    "44d88612fea8a8f36de82e1278abb02f": {
        "name": "EICAR Test File",
        "type": "Test Virus",
        "description": {
            "th": "ไฟล์จำลองมัลแวร์ที่ใช้ทดสอบระบบป้องกันไวรัส",
            "en": "Standard test file used to check antivirus functionality"
        }
    },
    "abcdef1234567890abcdef1234567890": {
        "name": "Trojan.Generic",
        "type": "Trojan",
        "description": {
            "th": "โทรจันทั่วไปที่อาจขโมยข้อมูลหรือเปิดช่องทางระยะไกล",
            "en": "Generic Trojan that may steal data or open remote access"
        }
    }
}

# 🟦 ภาษาเริ่มต้น: อังกฤษ
language = "en"

# 🟨 ฟังก์ชันแปลภาษา
def t(thai, english):
    return thai if language == "th" else english

# 🟨 แสดงเมนูเลือกภาษา
lang_choice = input("🌐 Choose language (th = ภาษาไทย, en = English) [default = en]: ").strip().lower()
if lang_choice == "th":
    language = "th"
elif lang_choice == "en" or lang_choice == "":
    language = "en"
else:
    print("⚠️ Invalid choice. Defaulting to English")
    language = "en"

# 🔐 คำนวณ hash ของไฟล์
def get_file_hash(file_path):
    hasher = hashlib.md5()
    try:
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hasher.update(chunk)
        return hasher.hexdigest()
    except:
        return None

# 🔍 สแกนไฟล์เดียว
def scan_file(file_path):
    print(f"\n📁 {t('กำลังสแกน', 'Scanning')}: {file_path}")
    
    file_hash = get_file_hash(file_path)
    file_type, _ = mimetypes.guess_type(file_path)
    file_size = os.path.getsize(file_path)

    if not file_hash:
        print(f"⚠️ {t('ไม่สามารถอ่านไฟล์ได้', 'Could not read file')}")
        return

    print(f"  🔹 {t('ประเภทไฟล์', 'File type')}: {file_type or t('ไม่ทราบ', 'Unknown')}")
    print(f"  🔸 {t('ขนาด', 'Size')}: {file_size / 1024:.2f} KB")
    print(f"  🔸 MD5: {file_hash}")

    if file_hash in known_malware:
        data = known_malware[file_hash]
        print(f"  ❌ {t('ตรวจพบมัลแวร์!', 'Malware Detected!')}")
        print(f"     ➤ {t('ชื่อ:', 'Name:')} {data['name']}")
        print(f"     ➤ {t('ประเภท:', 'Type:')} {data['type']}")
        print(f"     ➤ {t('คำอธิบาย:', 'Description:')} {data['description'][language]}")
    else:
        print(f"  ✅ {t('ไม่พบภัยคุกคามที่รู้จัก', 'No known threats found')}")
        if file_type is None:
            print(f"     ℹ️ {t('คำเตือน: ไม่สามารถระบุประเภทไฟล์ได้', 'Warning: File type is unknown')}")
        elif file_type in ['application/x-msdownload', 'application/octet-stream']:
            print(f"     ℹ️ {t('คำเตือน: ไฟล์นี้อาจเป็นโปรแกรมหรือ binary', 'Warning: This might be a binary/executable file')}")
        elif file_size > 10 * 1024 * 1024:
            print(f"     ℹ️ {t('คำเตือน: ไฟล์ขนาดใหญ่มาก อาจซ่อนโค้ดอันตราย', 'Warning: File is very large — may hide malicious code')}")
        else:
            print(f"     ➤ {t('เหตุผล: ไม่มีลายเซ็นมัลแวร์ และลักษณะไฟล์ปกติ', 'Reason: No malware signature and file looks normal')}")

# 🗜️ สแกนไฟล์ ZIP
def scan_zip(file_path):
    try:
        with zipfile.ZipFile(file_path, 'r') as zip_ref:
            extract_path = "__temp_zip_extract__"
            zip_ref.extractall(extract_path)
            print(f"\n📦 {t('แตก zip', 'Extracting zip')}: {file_path}")
            for root, _, files in os.walk(extract_path):
                for name in files:
                    scan_file(os.path.join(root, name))
            import shutil
            shutil.rmtree(extract_path)
    except:
        print(f"⚠️ {t('ไม่สามารถแตกไฟล์ zip ได้', 'Cannot extract zip file')}")

# 📁 สแกนโฟลเดอร์
def scan_folder(folder_path):
    for root, _, files in os.walk(folder_path):
        for name in files:
            file_path = os.path.join(root, name)
            if file_path.endswith(".zip"):
                scan_zip(file_path)
            else:
                scan_file(file_path)

# 🚀 เริ่มทำงาน
if __name__ == "__main__":
    print("🛡️  Simple Malware Scanner")
    print(f"🕒 {t('เริ่มการสแกน', 'Scan started at')}: {datetime.datetime.now()}\n")
    
    target = input(f"{t('📂 พิมพ์ path ของไฟล์หรือโฟลเดอร์ที่ต้องการสแกน', 'Enter path of file or folder to scan')}: ").strip()

    if os.path.isfile(target):
        if target.endswith(".zip"):
            scan_zip(target)
        else:
            scan_file(target)
    elif os.path.isdir(target):
        scan_folder(target)
    else:
        print(f"❌ {t('ไม่พบไฟล์หรือโฟลเดอร์ที่ระบุ', 'File or folder not found')}")
