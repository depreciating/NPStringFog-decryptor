import os
import re
import subprocess
import shutil
import base64
import hashlib

def get_md5(s):
    return hashlib.md5(s.encode('utf-8')).hexdigest()

def escape_str(s):
    s = s.replace('\\', '\\\\')
    s = s.replace('"', '\\"')
    s = s.replace('\n', '\\n')
    s = s.replace('\r', '\\r')
    s = s.replace('\t', '\\t')
    return s

def decrypt_fog4(hex_str, key):
    try:
        b = bytearray.fromhex(hex_str)
        for i in range(len(b)):
            b[i] ^= ord(key[i % len(key)])
        return b.decode('utf-8')
    except:
        return None

def find_best_key(temp_dir):
    np_candidates = [b""]
    possible_np2 = ["0OO0010101010100OOO1", "bin.mt"]
    npapp_content = ""

    if os.path.exists(".npapp"):
        with open(".npapp", "r", encoding="utf-8") as f:
            npapp_content = f.read().strip()

    for root, _, files in os.walk(temp_dir):
        if "NPApp.smali" in files:
            with open(os.path.join(root, "NPApp.smali"), "r", encoding="utf-8") as f:
                content = f.read()
            
            array_blocks = re.findall(r'\.array-data 1(.*?)\.end array-data', content, re.DOTALL)
            for block in array_blocks:
                byte_vals = re.findall(r'0x([0-9a-fA-F]{1,2})t', block)
                if byte_vals:
                    np_candidates.append(bytearray([int(b, 16) for b in byte_vals]))

            b64_strings = re.findall(r'const-string [vp]\d+, "([a-zA-Z0-9+/=]{10,})"', content)
            for b in b64_strings:
                try:
                    dec = base64.b64decode(b).decode('utf-8')
                    if '.' in dec:
                        possible_np2.append(dec)
                        possible_np2.append(dec.rsplit('.', 1)[0])
                except:
                    pass

    for root, dirs, files in os.walk(temp_dir):
        rel = os.path.relpath(root, temp_dir)
        parts = rel.split(os.sep)
        if len(parts) >= 2:
            possible_np2.append(".".join(parts[:2]))
            if len(parts) >= 3:
                possible_np2.append(".".join(parts[:3]))

    possible_np2 = list(set(possible_np2))
    possible_np3 = [npapp_content, ""]

    keys = set()
    for np_bytes in np_candidates:
        np_str = np_bytes.decode('utf-8', errors='ignore')
        for np2 in possible_np2:
            for np3 in possible_np3:
                keys.add(get_md5(np_str + np2 + np3))

    samples = []
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith(".smali"):
                with open(os.path.join(root, file), 'r', encoding='utf-8') as f:
                    file_content = f.read()
                matches = re.findall(r'const-string [vp]\d+, "([0-9A-F]{8,})"\s*\n\s*invoke-static(?:/range)? \{.*?\}, L.*?NPStringFog4;->decode', file_content)
                samples.extend(matches)
                if len(samples) > 100:
                    break
        if len(samples) > 100:
            break

    best_key = None
    max_score = -999999

    for key in keys:
        current_score = 0
        for s in samples:
            dec = decrypt_fog4(s, key)
            if dec is not None:
                for c in dec:
                    if c.isalnum():
                        current_score += 2
                    elif c in ' ._/-(),:;[]{}"\'':
                        current_score += 1
                    else:
                        current_score -= 5
            else:
                current_score -= 10
                
        if current_score > max_score:
            max_score = current_score
            best_key = key

    return best_key

def process_smali_file(filepath, key):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    pattern = r'const-string ([vp]\d+), "([0-9A-F]+)"\s*\n\s*invoke-static(?:/range)? \{.*?\}, L.*?NPStringFog4;->decode\(Ljava/lang/String;\)Ljava/lang/String;\s*\n\s*move-result-object \1'

    def replacer(match):
        reg = match.group(1)
        enc_str = match.group(2)
        dec_str = decrypt_fog4(enc_str, key)
        if dec_str is not None:
            return f'const-string {reg}, "{escape_str(dec_str)}"'
        return match.group(0)

    new_content = re.sub(pattern, replacer, content)

    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)

def deobfuscate_dex(input_dex, output_dex):
    temp_dir = "temp_smali_dir"
    
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        
    print("Disassembling...")
    subprocess.run(['java', '-jar', 'baksmali.jar', 'd', input_dex, '-o', temp_dir], check=True)

    key = find_best_key(temp_dir)
    print(f"Using decryption MD5 key: {key}")

    print("Patching Smali files...")
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith('.smali'):
                process_smali_file(os.path.join(root, file), key)

    print("Reassembling...")
    try:
        subprocess.run(['java', '-jar', 'smali.jar', 'a', temp_dir, '-o', output_dex], check=True)
        print(f"Successfully created {output_dex}")
    except subprocess.CalledProcessError:
        print("Reassembly failed. Check smali syntax errors.")
        
    shutil.rmtree(temp_dir)

if __name__ == "__main__":
    deobfuscate_dex("classes.dex", "classes_decrypted.dex")