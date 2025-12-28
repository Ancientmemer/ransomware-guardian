# ransomware_db.py

RANSOMWARE_DB = {
    ".djvu": {
        "name": "STOP / DJVU Ransomware",
        "decryptor": "Emsisoft Free Decryptor",
        "link": "https://www.nomoreransom.org"
    },
    ".locked": {
        "name": "Generic Ransomware",
        "decryptor": "Check NoMoreRansom",
        "link": "https://www.nomoreransom.org"
    },
    ".crypt": {
        "name": "Crypto Ransomware",
        "decryptor": "Check NoMoreRansom",
        "link": "https://www.nomoreransom.org"
    }
}

def identify_ransomware(file_path):
    for ext in RANSOMWARE_DB:
        if file_path.endswith(ext):
            return RANSOMWARE_DB[ext]
    return None
