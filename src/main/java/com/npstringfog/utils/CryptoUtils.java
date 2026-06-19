package com.npstringfog.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public class CryptoUtils {

    public static String decryptXor(String hexString, String key) {
        try {
            byte[] bytes = hexStringToByteArray(hexString);
            for (int i = 0; i < bytes.length; i++) {
                bytes[i] = (byte) (bytes[i] ^ ((byte) key.charAt(i % key.length())));
            }
            return new String(bytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static String decryptFog3(String b64String, String key) {
        try {
            String b64String2 = b64String.trim();
            int padding = (4 - (b64String2.length() % 4)) % 4;
            StringBuilder sb = new StringBuilder(b64String2);
            for (int i = 0; i < padding; i++) {
                sb.append("=");
            }
            b64String2 = sb.toString();
            
            byte[] decodedBytes = Base64.getDecoder().decode(b64String2);
            String hexString = new String(decodedBytes, StandardCharsets.UTF_8);
            byte[] encryptedBytes = hexStringToByteArray(hexString);
            for (int i2 = 0; i2 < encryptedBytes.length; i2++) {
                encryptedBytes[i2] = (byte) (encryptedBytes[i2] ^ ((byte) key.charAt(i2 % key.length())));
            }
            return new String(encryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

    public static String getMd5(String input) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            byte[] hashBytes = md.digest(input.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : hashBytes) {
                sb.append(String.format("%02x", Byte.valueOf(b)));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("MD5 algorithm not found", e);
        }
    }

    public static String escapeStr(String s) {
        if (s == null) {
            return null;
        }
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) 
                                 + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}