package com.npstringfog.decryptors;

import org.jf.dexlib2.AccessFlags;
import org.jf.dexlib2.Opcode;
import org.jf.dexlib2.builder.MutableMethodImplementation;
import org.jf.dexlib2.builder.instruction.BuilderInstruction21c;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.iface.instruction.Instruction;
import org.jf.dexlib2.iface.instruction.ReferenceInstruction;
import org.jf.dexlib2.iface.instruction.formats.Instruction11x;
import org.jf.dexlib2.iface.instruction.formats.Instruction21c;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.StringReference;
import org.jf.dexlib2.immutable.reference.ImmutableStringReference;

import javax.annotation.Nonnull;
import java.io.File;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.HashMap;
import java.util.Map;

public class NPStringFog5 extends BaseDecryptor {
    private String dynamicKey = "npmanager";
    private String npDir = "np";
    private Map<String, String> proxyMap = new HashMap<>();

    public void setNpDir(String npDir) {
        this.npDir = npDir;
    }

    @Override
    protected boolean shouldRemoveMethod(ClassDef classDef, Method method) {
        String fullSig = classDef.getType() + "->" + method.getName() + "()Ljava/lang/String;";
        return proxyMap.containsKey(fullSig);
    }

    @Override
    protected void initialize(DexFile dexFile) {
        for (ClassDef classDef : dexFile.getClasses()) {
            if (classDef.getType().contains("NPStringFog5")) {
                for (Method method : classDef.getMethods()) {
                    if (method.getName().equals("<clinit>")) {
                        MethodImplementation impl = method.getImplementation();
                        if (impl != null) {
                            String lastString = null;
                            for (Instruction inst : impl.getInstructions()) {
                                if (inst.getOpcode() == Opcode.CONST_STRING || inst.getOpcode() == Opcode.CONST_STRING_JUMBO) {
                                    lastString = ((StringReference) ((Instruction21c) inst).getReference()).getString();
                                } else if (inst.getOpcode() == Opcode.SPUT_OBJECT) {
                                    FieldReference fieldRef = (FieldReference) ((ReferenceInstruction) inst).getReference();
                                    if (fieldRef.getName().equals("KEY") && lastString != null) {
                                        this.dynamicKey = lastString;
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        System.out.println("[*] Using decryption key: " + dynamicKey);

        for (ClassDef classDef : dexFile.getClasses()) {
            String className = classDef.getType();
            for (Method method : classDef.getMethods()) {
                if (!method.getParameters().iterator().hasNext() && 
                    method.getReturnType().equals("Ljava/lang/String;") &&
                    AccessFlags.STATIC.isSet(method.getAccessFlags())) {
                    
                    MethodImplementation impl = method.getImplementation();
                    if (impl != null) {
                        boolean callsObfuscator = false;
                        String assetName = null;
                        for (Instruction inst : impl.getInstructions()) {
                            if (inst.getOpcode() == Opcode.CONST_STRING || inst.getOpcode() == Opcode.CONST_STRING_JUMBO) {
                                if (assetName == null) {
                                    assetName = ((StringReference) ((Instruction21c) inst).getReference()).getString();
                                }
                            } else if (inst.getOpcode() == Opcode.INVOKE_STATIC || inst.getOpcode() == Opcode.INVOKE_STATIC_RANGE) {
                                ReferenceInstruction refInst = (ReferenceInstruction) inst;
                                if (refInst.getReference() instanceof MethodReference) {
                                    String targetClass = ((MethodReference) refInst.getReference()).getDefiningClass();
                                    if (targetClass.contains("NPStringFog5") || targetClass.contains("Lnp/e/e2;")) {
                                        callsObfuscator = true;
                                    }
                                }
                            }
                        }
                        if (callsObfuscator && assetName != null) {
                            String decrypted = decryptAsset(assetName);
                            if (decrypted != null) {
                                proxyMap.put(className + "->" + method.getName() + "()Ljava/lang/String;", decrypted);
                            }
                        }
                    }
                }
            }
        }
        System.out.println("[*] Loaded " + proxyMap.size() + " decrypted strings from proxy methods.");
    }

    private String decryptAsset(String assetFilename) {
        try {
            File assetFile = new File(npDir, assetFilename);
            if (!assetFile.exists()) return null;
            String hexStr = new String(Files.readAllBytes(assetFile.toPath()), StandardCharsets.UTF_8).replaceAll("\\s+", "");
            byte[] b = hexStringToByteArray(hexStr);
            byte[] keyBytes = dynamicKey.getBytes(StandardCharsets.UTF_8);
            for (int i = 0; i < b.length; i++) b[i] = (byte) (b[i] ^ keyBytes[i % keyBytes.length]);
            return new String(b, StandardCharsets.UTF_8);
        } catch (Exception e) { return null; }
    }

    private byte[] hexStringToByteArray(String s) {
        byte[] data = new byte[s.length() / 2];
        for (int i = 0; i < s.length(); i += 2) data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i+1), 16));
        return data;
    }

    @Override
    protected MethodImplementation rewriteMethod(@Nonnull MethodImplementation methodImpl) {
        MutableMethodImplementation mutableMethod = new MutableMethodImplementation(methodImpl);
        boolean modified = false;
        int i = 0;
        while (i < mutableMethod.getInstructions().size() - 1) {
            Instruction current = mutableMethod.getInstructions().get(i);
            Instruction next = mutableMethod.getInstructions().get(i + 1);

            if ((current.getOpcode() == Opcode.INVOKE_STATIC || current.getOpcode() == Opcode.INVOKE_STATIC_RANGE) &&
                next.getOpcode() == Opcode.MOVE_RESULT_OBJECT) {

                ReferenceInstruction invokeInst = (ReferenceInstruction) current;
                if (invokeInst.getReference() instanceof MethodReference) {
                    MethodReference targetMethod = (MethodReference) invokeInst.getReference();
                    String fullSig = targetMethod.getDefiningClass() + "->" + targetMethod.getName() + "()Ljava/lang/String;";

                    if (proxyMap.containsKey(fullSig)) {
                        String decryptedStr = proxyMap.get(fullSig);
                        int targetRegister = ((Instruction11x) next).getRegisterA();

                        boolean removePrevDummy = false;
                        if (i > 0) {
                            Instruction prev = mutableMethod.getInstructions().get(i - 1);
                            if (prev.getOpcode() == Opcode.CONST_STRING || prev.getOpcode() == Opcode.CONST_STRING_JUMBO) {
                                if (((Instruction21c) prev).getRegisterA() == targetRegister) {
                                    String s = ((StringReference) ((Instruction21c) prev).getReference()).getString();
                                    if (s == null || s.isEmpty()) removePrevDummy = true;
                                }
                            }
                        }

                        BuilderInstruction21c newConstStr = new BuilderInstruction21c(Opcode.CONST_STRING, targetRegister, new ImmutableStringReference(decryptedStr));

                        if (removePrevDummy) {
                            mutableMethod.replaceInstruction(i - 1, newConstStr);
                            mutableMethod.removeInstruction(i);
                            mutableMethod.removeInstruction(i);
                        } else {
                            mutableMethod.replaceInstruction(i, newConstStr);
                            mutableMethod.removeInstruction(i + 1);
                            i++;
                        }
                        modified = true;
                        decryptedCount++;
                        continue;
                    }
                }
            }
            i++;
        }
        return modified ? mutableMethod : methodImpl;
    }
}