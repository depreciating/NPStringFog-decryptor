import os
import re
import subprocess
import shutil
import base64

def extract_dynamic_key(temp_dir):
    for root, _, files in os.walk(temp_dir):
        if "NPStringFog3.smali" in files:
            fog_path = os.path.join(root, "NPStringFog3.smali")
            with open(fog_path, 'r', encoding='utf-8') as f:
                content = f.read()
            key_pattern = r'const-string [vp]\d+, "(.*?)"\s*\n\s*sput-object [vp]\d+, L.*?NPStringFog3;->KEY:Ljava/lang/String;'
            match = re.search(key_pattern, content)
            if match:
                return match.group(1)
    return "npmanager"

def decrypt_npstringfog3(b64_str, key):
    try:
        b64_str = b64_str.strip()
        b64_str += "=" * ((4 - len(b64_str) % 4) % 4)
        b64_decoded = base64.b64decode(b64_str)
        hex_str = b64_decoded.decode('utf-8')
        encrypted_bytes = bytearray.fromhex(hex_str)
        key_len = len(key)
        for i in range(len(encrypted_bytes)):
            encrypted_bytes[i] ^= ord(key[i % key_len])
        return encrypted_bytes.decode('utf-8')
    except Exception:
        return None

def parse_string_pool(temp_dir, key):
    pool = {}
    pool_path = None
    
    for root, _, files in os.walk(temp_dir):
        if "StringPool.smali" in files:
            pool_path = os.path.join(root, "StringPool.smali")
            break
            
    if not pool_path:
        print("StringPool.smali not found!")
        return pool

    with open(pool_path, 'r', encoding='utf-8') as f:
        content = f.read()

    methods = content.split('.method public static ')[1:]
    for m in methods:
        method_name_match = re.match(r'([a-zA-Z0-9_]+)\(\)Ljava/lang/String;', m)
        if not method_name_match:
            continue
        method_name = method_name_match.group(1)

        array_data_match = re.search(r'\.array-data 1\s*(.*?)\s*\.end array-data', m, re.DOTALL)
        if array_data_match:
            bytes_str = array_data_match.group(1)
            byte_vals = re.findall(r'0x([0-9a-fA-F]{1,2})t', bytes_str)
            b64_bytes = bytearray([int(b, 16) for b in byte_vals])
            b64_str = b64_bytes.decode('utf-8', errors='ignore')
            decrypted = decrypt_npstringfog3(b64_str, key)
            if decrypted is not None:
                pool[method_name] = decrypted
        else:
            pool[method_name] = ""
            
    return pool

def escape_str(s):
    s = s.replace('\\', '\\\\')
    s = s.replace('"', '\\"')
    s = s.replace('\n', '\\n')
    s = s.replace('\r', '\\r')
    s = s.replace('\t', '\\t')
    return s

def process_smali_file(filepath, pool):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    pattern_with_const = r'const-string ([vp]\d+), ".*?"\s*\n\s*invoke-static(?:/range)? \{\}, L.*?/StringPool;->([a-zA-Z0-9_]+)\(\)Ljava/lang/String;\s*\n\s*move-result-object \1'
    
    def replacer_with_const(match):
        reg = match.group(1)
        method = match.group(2)
        if method in pool:
            return f'const-string {reg}, "{escape_str(pool[method])}"'
        return match.group(0)
        
    new_content = re.sub(pattern_with_const, replacer_with_const, content)

    pattern_invoke_only = r'invoke-static(?:/range)? \{\}, L.*?/StringPool;->([a-zA-Z0-9_]+)\(\)Ljava/lang/String;\s*\n\s*move-result-object ([vp]\d+)'
    
    def replacer_invoke_only(match):
        method = match.group(1)
        reg = match.group(2)
        if method in pool:
            return f'const-string {reg}, "{escape_str(pool[method])}"'
        return match.group(0)

    new_content = re.sub(pattern_invoke_only, replacer_invoke_only, new_content)

    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)

def deobfuscate_dex(input_dex, output_dex):
    temp_dir = "temp_smali_dir"
    
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        
    print("Disassembling...")
    subprocess.run(['java', '-jar', 'baksmali.jar', 'd', input_dex, '-o', temp_dir], check=True)

    dynamic_key = extract_dynamic_key(temp_dir)
    print(f"Using decryption key: {dynamic_key}")

    print("Parsing StringPool...")
    string_pool = parse_string_pool(temp_dir, dynamic_key)
    print(f"Successfully decrypted {len(string_pool)} strings.")

    print("Patching Smali files...")
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith('.smali'):
                process_smali_file(os.path.join(root, file), string_pool)

    print("Reassembling...")
    try:
        subprocess.run(['java', '-jar', 'smali.jar', 'a', temp_dir, '-o', output_dex], check=True)
        print(f"Successfully created {output_dex}")
    except subprocess.CalledProcessError:
        print("Reassembly failed. Check smali syntax errors.")
        
    shutil.rmtree(temp_dir)

if __name__ == "__main__":
    deobfuscate_dex("classes.dex", "classes_decrypted.dex")