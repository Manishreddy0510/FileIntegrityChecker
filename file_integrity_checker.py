import hashlib
import os
import json

HASH_FILE = "hashes.json"

def compute_hash(file_path):
    sha256 = hashlib.sha256()
    try:
        with open(file_path, "rb") as f:
            while chunk := f.read(8192):
                sha256.update(chunk)
        return sha256.hexdigest()
    except Exception as e:
        print(f"[ERROR] Could not read file {file_path}: {e}")
        return None

def scan_directory(directory):
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            full_path = os.path.join(root, file)
            hash_value = compute_hash(full_path)
            if hash_value:
                file_hashes[full_path] = hash_value
    return file_hashes

def save_hashes(hashes, filename=HASH_FILE):
    with open(filename, "w") as f:
        json.dump(hashes, f, indent=4)

def load_hashes(filename=HASH_FILE):
    if not os.path.exists(filename):
        print(f"[WARNING] Hash file '{filename}' not found.")
        return {}
    with open(filename, "r") as f:
        return json.load(f)

def verify_integrity(current_hashes, old_hashes):
    changed = False
    for path, current_hash in current_hashes.items():
        old_hash = old_hashes.get(path)
        if not old_hash:
            print(f"[NEW] {path}")
            changed = True
        elif current_hash != old_hash:
            print(f"[MODIFIED] {path}")
            changed = True

    for path in old_hashes:
        if path not in current_hashes:
            print(f"[DELETED] {path}")
            changed = True

    if not changed:
        print("[OK] No changes detected.")

def main():
    print("📂 File Integrity Checker")
    mode = input("Enter mode (init/check): ").strip().lower()
    directory = input("Enter directory to scan: ").strip()

    if not os.path.isdir(directory):
        print(f"[ERROR] Directory '{directory}' does not exist.")
        return

    current_hashes = scan_directory(directory)

    if mode == "init":
        save_hashes(current_hashes)
        print(f"[INFO] Hashes saved to {HASH_FILE}")
    elif mode == "check":
        old_hashes = load_hashes()
        verify_integrity(current_hashes, old_hashes)
    else:
        print("[ERROR] Invalid mode. Use 'init' or 'check'.")

if __name__ == "__main__":
    main()
