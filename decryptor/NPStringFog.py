import os
import re
import subprocess
import shutil

def extract_dynamic_key(temp_dir):
    fog_path = os.path.join(temp_dir, "obfuse", "NPStringFog.smali")
    if not os.path.exists(fog_path):
        return "npmanager"
    
    with open(fog_path, 'r', encoding='utf-8') as f:
        content = f.read()
        
    key_pattern = r'const-string v\d+, "(.*?)"\s*\n\s*sput-object v\d+, Lobfuse/NPStringFog;->KEY:Ljava/lang/String;'
    match = re.search(key_pattern, content)
    
    if match:
        return match.group(1)
    return "npmanager"

def decode_easyobf(encoded_str, key):
    key_len = len(key)
    try:
        byte_array = bytearray.fromhex(encoded_str)
        for i in range(len(byte_array)):
            byte_array[i] ^= ord(key[i % key_len])
        return byte_array.decode('utf-8', errors='ignore')
    except ValueError:
        return None

def process_smali_file(filepath, decryption_key):
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    pattern = r'const-string (v\d+), "(.*?)"\s*\n\s*invoke-static(?:/range)? \{.*?\}, Lobfuse/NPStringFog;->decode\(Ljava/lang/String;\)Ljava/lang/String;\s*\n\s*move-result-object \1'

    def replacer(match):
        reg = match.group(1)
        enc_str = match.group(2)
        
        dec_str = decode_easyobf(enc_str, decryption_key)
        
        if dec_str is not None:
            dec_str = dec_str.replace('\\', '\\\\')
            dec_str = dec_str.replace('"', '\\"')
            dec_str = dec_str.replace('\n', '\\n')
            dec_str = dec_str.replace('\r', '\\r')
            dec_str = dec_str.replace('\t', '\\t')
            return f'const-string {reg}, "{dec_str}"'
        return match.group(0)

    new_content = re.sub(pattern, replacer, content)

    if new_content != content:
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(new_content)

def deobfuscate_dex(input_dex, output_dex):
    temp_dir = "temp_smali_dir"
    
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        
    subprocess.run(['java', '-jar', 'baksmali.jar', 'd', input_dex, '-o', temp_dir], check=True)

    dynamic_key = extract_dynamic_key(temp_dir)
    print(f"Using decryption key: {dynamic_key}")

    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith('.smali'):
                process_smali_file(os.path.join(root, file), dynamic_key)

    try:
        subprocess.run(['java', '-jar', 'smali.jar', 'a', temp_dir, '-o', output_dex], check=True)
        print(f"Successfully created {output_dex}")
    except subprocess.CalledProcessError:
        print("Reassembly failed. Check smali syntax errors.")
        
    shutil.rmtree(temp_dir)

if __name__ == "__main__":
    deobfuscate_dex("classes.dex", "classes_decrypted.dex")