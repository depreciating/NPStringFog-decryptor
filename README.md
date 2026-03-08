# NPStringFog Auto-Decryptor

A fully automated tool to deobfuscate Android DEX files protected by various versions of the NPStringFog obfuscator. 

## Supported Versions
* **NPStringFog** (Standard XOR)
* **NPStringFog3** (StringPool Array Variant)
* **NPStringFog4** (MD5 Integrity / NPApp Variant)
* **NPStringFog5** (Asset Mapping / Proxy Method Variant)

## How to Use (Cloud / No Installation)
You can run this decryptor entirely in the cloud for free using GitHub Actions.

1. Click **Add file -> Upload files** and upload your obfuscated `classes.dex` to the main folder of this repository.
   * *For Fog4:* Upload the `.npapp` file if it exists.
   * *For Fog5:* Upload the `np/` directory containing the encrypted asset files.
2. Commit the changes.
3. Go to the **Actions** tab at the top of the repository.
4. Click **NP-Deobfuscator-Cloud** on the left sidebar.
5. Click **Run workflow** on the right side.
6. Wait for the job to complete (usually ~30 seconds). Click on the completed job and download the `Decrypted-DEX.zip` file from the **Artifacts** section at the bottom.

## How to Use (Local)
Ensure you have `python3` and `java` installed. Place `baksmali.jar` and `smali.jar` in the same directory as the script.

```bash
python decrypt.py classes.dex