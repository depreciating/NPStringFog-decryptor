import os
import sys
import subprocess

def detect_obfuscator(dex_path):
    print(f"[*] Scanning {dex_path} for obfuscator signatures...")
    try:
        with open(dex_path, 'rb') as f:
            content = f.read()
    except FileNotFoundError:
        print(f"[!] Error: {dex_path} not found.")
        sys.exit(1)

    if b"NPStringFog5" in content:
        return "decryptor/NPStringFog5.py"
    elif b"NPStringFog4" in content or b"NPApp" in content:
        return "decryptor/NPApp.py"
    elif b"StringPool" in content and b"NPStringFog3" in content:
        return "decryptor/NPStringFog3.py"
    elif b"NPStringFog" in content:
        return "decryptor/NPStringFog.py"
    else:
        return None

def main():
    input_dex = sys.argv[1] if len(sys.argv) > 1 else "classes.dex"
    script_to_run = detect_obfuscator(input_dex)
    
    if not script_to_run:
        print("[-] No known NPStringFog variations detected.")
        sys.exit(0)
        
    print(f"[+] Detected match! Routing to: {script_to_run}")
    
    if not os.path.exists(script_to_run):
        print(f"[!] Error: {script_to_run} is missing. Make sure your 'decryptor' folder exists.")
        sys.exit(1)
        
    try:
        subprocess.run([sys.executable, script_to_run, input_dex], check=True)
    except subprocess.CalledProcessError:
        print(f"[!] {script_to_run} encountered an error.")
        sys.exit(1)

if __name__ == "__main__":
    main()