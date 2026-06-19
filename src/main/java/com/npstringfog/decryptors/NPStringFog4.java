package com.npstringfog.decryptors;

import com.npstringfog.utils.CryptoUtils;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.MutableMethodImplementation;
import org.jf.dexlib2.builder.instruction.BuilderInstruction21c;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.formats.ArrayPayload;
import org.jf.dexlib2.iface.instruction.formats.Instruction11x;
import org.jf.dexlib2.iface.instruction.formats.Instruction21c;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.StringReference;
import org.jf.dexlib2.immutable.reference.ImmutableStringReference;

import javax.annotation.Nonnull;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class NPStringFog4 extends BaseDecryptor {
    private String bestKey = null;
    private String npappPath = ".npapp";

    public void setNpappPath(String path) {
        this.npappPath = path;
    }

    @Override
    protected void initialize(DexFile dexFile) {
        System.out.println("[*] Searching AST to brute force NPApp keys...");

        List<byte[]> npCandidates = new ArrayList<>();
        Set<String> np2Candidates = new HashSet<>();
        List<String> np3Candidates = new ArrayList<>();

        // Add defaults
        npCandidates.add(new byte[0]);
        np2Candidates.add("0OO0010101010100OOO1");
        np2Candidates.add("bin.mt");

        // 1. Gather array payloads and base64 strings from the NPApp class
        for (ClassDef classDef : dexFile.getClasses()) {
            if (classDef.getType().contains("NPApp;") || classDef.getType().contains("NPStringFog4;")) {
                for (Method method : classDef.getMethods()) {
                    MethodImplementation methodImpl = method.getImplementation();
                    if (methodImpl != null) {
                        for (Instruction inst : methodImpl.getInstructions()) {
                            if (inst instanceof ArrayPayload) {
                                List<Number> elements = ((ArrayPayload) inst).getArrayElements();
                                byte[] npBytes = new byte[elements.size()];
                                for (int i = 0; i < elements.size(); i++) {
                                    npBytes[i] = elements.get(i).byteValue();
                                }
                                npCandidates.add(npBytes);
                            } else if (inst.getOpcode() == Opcode.CONST_STRING) {
                                String s = ((StringReference) ((Instruction21c) inst).getReference()).getString();
                                if (!s.isEmpty()) {
                                    np2Candidates.add(s);
                                    // Try decoding Base64 strings (Python translation)
                                    if (s.length() >= 10 && s.matches("^[a-zA-Z0-9+/=]+$")) {
                                        try {
                                            String decoded = new String(Base64.getDecoder().decode(s), StandardCharsets.UTF_8);
                                            if (decoded.contains(".")) {
                                                np2Candidates.add(decoded);
                                                int lastDot = decoded.lastIndexOf('.');
                                                if (lastDot != -1) {
                                                    np2Candidates.add(decoded.substring(0, lastDot));
                                                }
                                            }
                                        } catch (Exception ignored) {}
                                    }
                                }
                            }
                        }
                    }
                }
            }
            
            // 2. Extract package names directly from AST paths (Python translation)
            String type = classDef.getType(); // e.g., "Lcom/example/app/MainActivity;"
            if (type.startsWith("L")) {
                String[] parts = type.substring(1).split("/");
                if (parts.length >= 2) {
                    np2Candidates.add(parts[0] + "." + parts[1]);
                }
                if (parts.length >= 3) {
                    np2Candidates.add(parts[0] + "." + parts[1] + "." + parts[2]);
                }
            }
        }

        // 3. Read the .npapp file from disk (np3)
        np3Candidates.add(""); // Empty string is always a candidate
        try {
            File npappFile = new File(this.npappPath);
            if (npappFile.exists()) {
                System.out.println("[*] Found " + this.npappPath + ", reading contents...");
                String content = new String(Files.readAllBytes(npappFile.toPath()), StandardCharsets.UTF_8).trim();
                np3Candidates.add(content);
            }
        } catch (Exception e) {
            System.out.println("[!] Failed to read .npapp file: " + e.getMessage());
        }

        // 4. Generate ALL possible MD5 key combinations
        Set<String> md5Candidates = new HashSet<>();
        for (byte[] npBytes : npCandidates) {
            String npString = new String(npBytes, StandardCharsets.UTF_8);
            for (String np2 : np2Candidates) {
                for (String np3 : np3Candidates) {
                    String baseString = npString + np2 + np3;
                    md5Candidates.add(CryptoUtils.getMd5(baseString));
                }
            }
        }

        // 5. Gather up to 100 sample encrypted strings
        List<String> samples = new ArrayList<>();
        outer:
        for (ClassDef classDef : dexFile.getClasses()) {
            for (Method method : classDef.getMethods()) {
                MethodImplementation methodImpl = method.getImplementation();
                if (methodImpl != null) {
                    Instruction prev = null;
                    for (Instruction inst : methodImpl.getInstructions()) {
                        if (inst.getOpcode() == Opcode.INVOKE_STATIC || inst.getOpcode() == Opcode.INVOKE_STATIC_RANGE) {
                            ReferenceInstruction refInst = (ReferenceInstruction) inst;
                            if (refInst.getReference() instanceof MethodReference) {
                                MethodReference mRef = (MethodReference) refInst.getReference();
                                if (mRef.getName().equals("decode") && prev != null && prev.getOpcode() == Opcode.CONST_STRING) {
                                    String hexStr = ((StringReference) ((Instruction21c) prev).getReference()).getString();
                                    if (hexStr.length() >= 8 && hexStr.matches("[0-9A-Fa-f]+")) {
                                        samples.add(hexStr);
                                        if (samples.size() >= 100) break outer;
                                    }
                                }
                            }
                        }
                        prev = inst;
                    }
                }
            }
        }

        // 6. Find the best key
        int maxScore = -999999;
        
        for (String candidateKey : md5Candidates) {
            int currentScore = 0;
            
            for (String s : samples) {
                String dec = CryptoUtils.decryptXor(s, candidateKey);
                if (dec != null) {
                    for (char c : dec.toCharArray()) {
                        if (Character.isLetterOrDigit(c)) {
                            currentScore += 2;
                        } else if (" ._/-(),:;[]{}\"'".indexOf(c) != -1) {
                            currentScore += 1;
                        } else {
                            currentScore -= 5;
                        }
                    }
                } else {
                    currentScore -= 10;
                }
            }
            
            if (currentScore > maxScore) {
                maxScore = currentScore;
                this.bestKey = candidateKey;
            }
        }

        System.out.println("[+] Best valid key found! MD5: " + this.bestKey);
        // if (!samples.isEmpty()) {
        //     System.out.println("[+] Example Output: \"" + CryptoUtils.decryptXor(samples.get(0), this.bestKey) + "\"");
        // }
    }

    @Override
    protected MethodImplementation rewriteMethod(@Nonnull MethodImplementation methodImpl) {
        MutableMethodImplementation mutableMethod = new MutableMethodImplementation(methodImpl);
        boolean modified = false;

        for (int i = 0; i < mutableMethod.getInstructions().size() - 2; i++) {
            Instruction current = mutableMethod.getInstructions().get(i);
            Instruction next = mutableMethod.getInstructions().get(i + 1);
            Instruction nextNext = mutableMethod.getInstructions().get(i + 2);

            boolean isInvokeStatic = next.getOpcode() == Opcode.INVOKE_STATIC || 
                                     next.getOpcode() == Opcode.INVOKE_STATIC_RANGE;

            if (current.getOpcode() == Opcode.CONST_STRING && 
                isInvokeStatic && 
                nextNext.getOpcode() == Opcode.MOVE_RESULT_OBJECT) {
                
                Instruction21c constStrInst = (Instruction21c) current;
                ReferenceInstruction invokeInst = (ReferenceInstruction) next;
                Instruction11x moveResultInst = (Instruction11x) nextNext;

                if (constStrInst.getReference() instanceof StringReference && 
                    invokeInst.getReference() instanceof MethodReference) {
                    
                    String encryptedHex = ((StringReference) constStrInst.getReference()).getString();
                    MethodReference targetMethod = (MethodReference) invokeInst.getReference();

                    if (targetMethod.getName().equals("decode")) {
                        
                        String decryptedStr = CryptoUtils.decryptXor(encryptedHex, bestKey);
                        if (decryptedStr != null) {
                            
                            int targetRegister = moveResultInst.getRegisterA();
                            BuilderInstruction21c newConstStr = new BuilderInstruction21c(
                                    Opcode.CONST_STRING, 
                                    targetRegister, 
                                    new ImmutableStringReference(decryptedStr)
                            );
                            
                            mutableMethod.replaceInstruction(i, newConstStr);
                            mutableMethod.removeInstruction(i + 1); 
                            mutableMethod.removeInstruction(i + 1); 
                            
                            modified = true;
                            // decryptedCount++; // Assuming this is tracked in BaseDecryptor
                        }
                    }
                }
            }
        }
        return modified ? mutableMethod : methodImpl;
    }
}