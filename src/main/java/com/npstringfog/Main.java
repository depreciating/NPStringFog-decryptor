package com.npstringfog;

import com.npstringfog.decryptors.*;
import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;

public class Main {
    public static void main(String[] args) throws Exception {
        printWatermark();

        String inputDex = "classes.dex";
        String outputDex = null;
        String npappPath = ".npapp";
        String npDir = "np";

        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-i":
                    if (i + 1 < args.length) inputDex = args[++i];
                    break;
                case "-o":
                    if (i + 1 < args.length) outputDex = args[++i];
                    break;
                case "-n":
                    if (i + 1 < args.length) npappPath = args[++i];
                    break;
                case "-d":
                    if (i + 1 < args.length) npDir = args[++i];
                    break;
                case "-h":
                case "--help":
                    printUsage();
                    System.exit(0);
            }
        }

        if (outputDex == null) {
            outputDex = inputDex.replace(".dex", "_decrypted.dex");
        }

        if (!new File(inputDex).exists()) {
            System.out.println("[-] Input file not found: " + inputDex);
            printUsage();
            System.exit(1);
        }

        System.out.println("[*] Scanning " + inputDex + " for obfuscator signatures...");
        byte[] contentBytes = Files.readAllBytes(Paths.get(inputDex));
        String contentStr = new String(contentBytes, "ISO-8859-1");

        BaseDecryptor decryptor = null;

        if (contentStr.contains("NPStringFog5")) {
            decryptor = new NPStringFog5();
            ((NPStringFog5) decryptor).setNpDir(npDir);
        } else if (contentStr.contains("NPStringFog4") || contentStr.contains("NPApp")) {
            decryptor = new NPStringFog4();
            ((NPStringFog4) decryptor).setNpappPath(npappPath);
        } else if (contentStr.contains("StringPool") && contentStr.contains("NPStringFog3")) {
            decryptor = new NPStringFog3();
        } else if (contentStr.contains("NPStringFog")) {
            decryptor = new NPStringFog();
        } else {
            System.out.println("[-] No known NPStringFog variations detected.");
            System.exit(0);
        }

        System.out.println("[+] Detected match! Routing to: " + decryptor.getClass().getSimpleName());
        decryptor.process(inputDex, outputDex);
    }

    private static void printWatermark() {
        // Clear screen + scrollback buffer
        System.out.print("\033[H\033[2J\033[3J");
        System.out.flush();

        System.out.println("  /$$$$$$  /$$   /$$  /$$$$$$  /$$$$$$/$$$$   /$$$$$$  /$$   /$$");
        System.out.println(" |____  $$| $$  | $$ /$$__  $$| $$_  $$_  $$ |____  $$|  $$ /$$/");
        System.out.println("  /$$$$$$$| $$  | $$| $$  \\ $$| $$ \\ $$ \\ $$  /$$$$$$$ \\  $$$$/ ");
        System.out.println(" /$$__  $$| $$  | $$| $$  | $$| $$ | $$ | $$ /$$__  $$  >$$  $$ ");
        System.out.println("|  $$$$$$$|  $$$$$$$|  $$$$$$/| $$ | $$ | $$|  $$$$$$$ /$$/\\  $$");
        System.out.println(" \\_______/ \\____  $$ \\______/ |__/ |__/ |__/ \\_______/|__/  \\__/");
        System.out.println("           /$$  | $$                                            ");
        System.out.println("          |  $$$$$$/                                            ");
        System.out.println("           \\______/                                             ");
        
        // Shortened border (64 chars) to prevent wrapping on zoomed terminals
        System.out.println("================================================================");
        System.out.println("                NPStringFog Multi-Decryptor v2.0                ");
        System.out.println("================================================================");
        System.out.println();
    }

    private static void printUsage() {
        System.out.println("Usage: java -jar npdecryptor.jar [options]");
        System.out.println("Options:");
        System.out.println("  -i <file>    Input DEX file (default: classes.dex)");
        System.out.println("  -o <file>    Output DEX file (default: input_decrypted.dex)");
        System.out.println("  -n <path>    Path to .npapp file for Fog4 (default: .npapp)");
        System.out.println("  -d <dir>     Path to asset directory for Fog5 (default: np)");
    }
}