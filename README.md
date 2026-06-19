# NPStringFog Auto-Decryptor

A high-performance, automated Java tool to deobfuscate Android DEX files protected by various versions of the NPStringFog obfuscator. Built on top of `dexlib2` for lightning-fast, in-memory Abstract Syntax Tree (AST) instruction patching.

## Contact Me
If you run into any issues, have questions, or want to discuss reverse engineering, feel free to reach out:
* **Telegram:** [@depreciatin](https://t.me/depreciatin)

## Supported Versions
* **NPStringFog** (Standard XOR with Overloaded Trap Bypass Heuristics)
* **NPStringFog3** (StringPool Base64 Array Variant)
* **NPStringFog4** (Static Brute-Force Heuristic Score MD5 / NPApp Variant)
* **NPStringFog5** (In-Memory Instruction Devirtualization & Dead Proxy Method Purging)

## Quick Start (Pre-Compiled Release)
If you don't want to build from source, you can download the ready-to-run execution file directly from the **Releases** tab of this repository.

1. Go to the **Releases** section on the right side of the repository page.
2. Download the latest `npdecryptor.jar`.
3. Open your terminal/Termux in that folder and execute directly using Java:

```bash
Usage: java -jar npdecryptor.jar [options]
Options:
  -i <file>    Input DEX file (default: classes.dex)
  -o <file>    Output DEX file (default: input_decrypted.dex)
  -n <path>    Path to .npapp file for Fog4 (default: .npapp)
  -d <dir>     Path to asset directory for Fog5 (default: np)
```

## Installation from Source
If you prefer to audit and compile the binaries locally, ensure you have a standard JDK installed and run the build sequence from the repository root:

```bash
git clone https://github.com/depreciating/NPStringFog-decryptor.git
cd NPStringFog-decryptor
./gradlew jar
