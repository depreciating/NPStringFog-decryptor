import os
import re
import subprocess
import shutil
import sys

def escape_str(s):
    s = s.replace('\\', '\\\\')
    s = s.replace('"', '\\"')
    s = s.replace('\n', '\\n')
    s = s.replace('\r', '\\r')
    s = s.replace('\t', '\\t')
    return s

def extract_dynamic_key(temp_dir):
    for root, _, files in os.walk(temp_dir):
        if "NPStringFog5.smali" in files:
            fog_path = os.path.join(root, "NPStringFog5.smali")
            with open(fog_path, 'r', encoding='utf-8') as f:
                content = f.read()
            key_pattern = r'const-string [vp]\d+, "(.*?)"\s*\n\s*sput-object [vp]\d+, L.*?NPStringFog5;->KEY:Ljava/lang/String;'
            match = re.search(key_pattern, content)
            if match:
                return match.group(1)
    return "npmanager"

def get_decrypted_string(asset_filename, key, active_np_dir):
    if not active_np_dir:
        return None
    asset_path = os.path.join(active_np_dir, asset_filename)
    if not os.path.exists(asset_path):
        return None
    with open(asset_path, 'r', encoding='utf-8') as f:
        hex_str = f.read().strip().replace('\n', '').replace('\r', '').replace(' ', '')
    try:
        b = bytearray.fromhex(hex_str)
        for i in range(len(b)):
            b[i] ^= ord(key[i % len(key)])
        return b.decode('utf-8')
    except:
        return None

def deobfuscate_dex(input_dex, output_dex):
    temp_dir = "temp_smali_dir"
    
    if os.path.exists(temp_dir):
        shutil.rmtree(temp_dir)
        
    print("Disassembling...")
    subprocess.run(['java', '-jar', 'baksmali.jar', 'd', input_dex, '-o', temp_dir], check=True)

    dynamic_key = extract_dynamic_key(temp_dir)
    print(f"Using decryption key: {dynamic_key}")

    active_np_dir = None
    for d in ["np", "assets/np"]:
        if os.path.exists(d) and os.path.isdir(d):
            active_np_dir = d
            break
            
    if not active_np_dir:
        print("Warning: 'np' folder not found. Please extract it to the current directory.")

    proxy_map = {}
    method_pattern = re.compile(r'(\.method .*?\.end method)', re.DOTALL)

    print("Parsing and removing proxy methods...")
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith('.smali'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                class_match = re.search(r'\.class.*? (L.*?;)', content)
                if not class_match:
                    continue
                class_name = class_match.group(1)
                
                def method_replacer(match):
                    full_method = match.group(1)
                    if '()Ljava/lang/String;' in full_method:
                        if 'NPStringFog5' in full_method or 'Lnp/e/e2;' in full_method:
                            sig_match = re.search(r'\.method.*? static ([a-zA-Z0-9_$]+)\(\)Ljava/lang/String;', full_method)
                            if sig_match:
                                method_name = sig_match.group(1)
                                asset_match = re.search(r'const-string [vp]\d+, "(.*?)"', full_method)
                                if asset_match:
                                    asset_name = asset_match.group(1)
                                    full_sig = f"{class_name}->{method_name}()Ljava/lang/String;"
                                    dec_str = get_decrypted_string(asset_name, dynamic_key, active_np_dir)
                                    if dec_str is not None:
                                        proxy_map[full_sig] = dec_str
                                        return ""
                    return full_method

                new_content = method_pattern.sub(method_replacer, content)
                
                if new_content != content:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)

    print(f"Successfully decrypted and removed {len(proxy_map)} proxy methods.")

    print("Patching Smali files...")
    pattern = r'(const-string ([vp]\d+), ".*?"\s*\n\s*)?invoke-static(?:/range)? \{.*?\}, (L.*?;->[a-zA-Z0-9_$]+\(\)Ljava/lang/String;)\s*\n\s*move-result-object ([vp]\d+)'
    
    for root, _, files in os.walk(temp_dir):
        for file in files:
            if file.endswith('.smali'):
                filepath = os.path.join(root, file)
                with open(filepath, 'r', encoding='utf-8') as f:
                    content = f.read()

                def replacer(match):
                    full_match = match.group(0)
                    prev_full = match.group(1)
                    prev_reg = match.group(2)
                    full_sig = match.group(3)
                    res_reg = match.group(4)
                    
                    if full_sig in proxy_map:
                        dec_str = proxy_map[full_sig]
                        new_inst = f'const-string {res_reg}, "{escape_str(dec_str)}"'
                        
                        if prev_full:
                            if prev_reg == res_reg:
                                return new_inst
                            else:
                                return prev_full + new_inst
                        else:
                            return new_inst
                            
                    return full_match

                new_content = re.sub(pattern, replacer, content)

                if new_content != content:
                    with open(filepath, 'w', encoding='utf-8') as f:
                        f.write(new_content)

    print("Reassembling...")
    try:
        subprocess.run(['java', '-jar', 'smali.jar', 'a', temp_dir, '-o', output_dex], check=True)
        print(f"Successfully created {output_dex}")
    except subprocess.CalledProcessError:
        print("Reassembly failed. Check smali syntax errors.")
        
    shutil.rmtree(temp_dir)

if __name__ == "__main__":
    input_dex = sys.argv[1] if len(sys.argv) > 1 else "classes.dex"
    output_dex = sys.argv[2] if len(sys.argv) > 2 else input_dex.replace(".dex", "_decrypted.dex")
    deobfuscate_dex(input_dex, output_dex)