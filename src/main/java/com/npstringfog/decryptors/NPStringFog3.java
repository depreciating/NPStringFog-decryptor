package com.npstringfog.decryptors;

import com.npstringfog.utils.CryptoUtils;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import javax.annotation.Nonnull;
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
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.StringReference;
import org.jf.dexlib2.immutable.reference.ImmutableStringReference;

public class NPStringFog3 extends BaseDecryptor {
    private String dynamicKey = "npmanager";
    private Map<String, String> stringPool = new HashMap<>();

    @Override
    protected void initialize(DexFile dexFile) {
        System.out.println("[*] Searching AST for NPStringFog3 key and StringPools...");
        
        // 1. Locate dynamic key in the static initializer (<clinit>) of NPStringFog3 classes
        for (ClassDef classDef : dexFile.getClasses()) {
            if (classDef.getType().contains("NPStringFog3;")) {
                for (Method method : classDef.getMethods()) {
                    MethodImplementation methodImpl = method.getImplementation();
                    if (method.getName().equals("<clinit>") && methodImpl != null) {
                        Instruction prevInst = null;
                        for (Instruction inst : methodImpl.getInstructions()) {
                            if (inst.getOpcode() == Opcode.SPUT_OBJECT) {
                                if (inst instanceof ReferenceInstruction) {
                                    ReferenceInstruction sputInst = (ReferenceInstruction) inst;
                                    if (sputInst.getReference() instanceof FieldReference) {
                                        FieldReference fieldRef = (FieldReference) sputInst.getReference();
                                        if (fieldRef.getName().equals("KEY") && prevInst != null && prevInst.getOpcode() == Opcode.CONST_STRING) {
                                            this.dynamicKey = ((StringReference) ((Instruction21c) prevInst).getReference()).getString();
                                            System.out.println("[+] Found dynamic key: " + this.dynamicKey);
                                        }
                                    }
                                }
                            }
                            prevInst = inst;
                        }
                    }
                }
            }
        }

        // 2. Extract and pre-decrypt the StringPool array elements
        int poolDecrypted = 0;
        for (ClassDef classDef2 : dexFile.getClasses()) {
            if (classDef2.getType().contains("StringPool;")) {
                for (Method method2 : classDef2.getMethods()) {
                    MethodImplementation methodImpl2 = method2.getImplementation();
                    if (method2.getReturnType().equals("Ljava/lang/String;") && !method2.getName().equals("<init>") && methodImpl2 != null) {
                        boolean foundArrayData = false;
                        
                        for (Instruction inst : methodImpl2.getInstructions()) {
                            if (inst instanceof ArrayPayload) {
                                foundArrayData = true;
                                ArrayPayload payload = (ArrayPayload) inst;
                                List<Number> elements = payload.getArrayElements();
                                byte[] b64Bytes = new byte[elements.size()];
                                for (int i = 0; i < elements.size(); i++) {
                                    b64Bytes[i] = elements.get(i).byteValue();
                                }
                                String b64Str = new String(b64Bytes, StandardCharsets.UTF_8);
                                String decryptedStr = CryptoUtils.decryptFog3(b64Str, this.dynamicKey);
                                if (decryptedStr != null) {
                                    String methodSignature = classDef2.getType() + "->" + method2.getName() + "()Ljava/lang/String;";
                                    this.stringPool.put(methodSignature, decryptedStr);
                                    poolDecrypted++;
                                }
                            }
                        }
                        
                        if (!foundArrayData) {
                            String methodSignature2 = classDef2.getType() + "->" + method2.getName() + "()Ljava/lang/String;";
                            this.stringPool.put(methodSignature2, "");
                            poolDecrypted++;
                        }
                    }
                }
            }
        }
        System.out.println("[+] Decrypted " + poolDecrypted + " strings into memory pool.");
    }

    @Override
    protected MethodImplementation rewriteMethod(@Nonnull MethodImplementation methodImpl) {
        MutableMethodImplementation mutableMethod = new MutableMethodImplementation(methodImpl);
        boolean modified = false;
        
        // Loop using safer instruction inspections to prevent class-cast failures
        for (int i = 0; i < mutableMethod.getInstructions().size() - 1; i++) {
            Instruction current = mutableMethod.getInstructions().get(i);
            Instruction next = mutableMethod.getInstructions().get(i + 1);

            boolean inst1IsInvoke = current.getOpcode() == Opcode.INVOKE_STATIC || current.getOpcode() == Opcode.INVOKE_STATIC_RANGE;
            boolean inst2IsInvoke = next.getOpcode() == Opcode.INVOKE_STATIC || next.getOpcode() == Opcode.INVOKE_STATIC_RANGE;

            // Pattern 1: CONST_STRING + INVOKE_STATIC + MOVE_RESULT_OBJECT
            if (i < mutableMethod.getInstructions().size() - 2) {
                Instruction nextNext = mutableMethod.getInstructions().get(i + 2);
                if (current.getOpcode() == Opcode.CONST_STRING && inst2IsInvoke && nextNext.getOpcode() == Opcode.MOVE_RESULT_OBJECT) {
                    if (next instanceof ReferenceInstruction) {
                        ReferenceInstruction invokeInst = (ReferenceInstruction) next;
                        if (invokeInst.getReference() instanceof MethodReference) {
                            MethodReference methodRef = (MethodReference) invokeInst.getReference();
                            String methodSignature = methodRef.getDefiningClass() + "->" + methodRef.getName() + "()Ljava/lang/String;";
                            
                            if (this.stringPool.containsKey(methodSignature)) {
                                String decryptedStr = this.stringPool.get(methodSignature);
                                int targetReg = ((Instruction11x) nextNext).getRegisterA();
                                BuilderInstruction21c newConstStr = new BuilderInstruction21c(Opcode.CONST_STRING, targetReg, new ImmutableStringReference(decryptedStr));
                                
                                mutableMethod.replaceInstruction(i, newConstStr);
                                mutableMethod.removeInstruction(i + 1);
                                mutableMethod.removeInstruction(i + 1);
                                modified = true;
                                this.decryptedCount++;
                            }
                        }
                    }
                }
            }

            // Pattern 2: INVOKE_STATIC + MOVE_RESULT_OBJECT
            if (inst1IsInvoke && next.getOpcode() == Opcode.MOVE_RESULT_OBJECT) {
                if (current instanceof ReferenceInstruction) {
                    ReferenceInstruction invokeInst2 = (ReferenceInstruction) current;
                    if (invokeInst2.getReference() instanceof MethodReference) {
                        MethodReference methodRef2 = (MethodReference) invokeInst2.getReference();
                        String methodSignature2 = methodRef2.getDefiningClass() + "->" + methodRef2.getName() + "()Ljava/lang/String;";
                        
                        if (this.stringPool.containsKey(methodSignature2)) {
                            String decryptedStr2 = this.stringPool.get(methodSignature2);
                            int targetReg2 = ((Instruction11x) next).getRegisterA();
                            BuilderInstruction21c newConstStr2 = new BuilderInstruction21c(Opcode.CONST_STRING, targetReg2, new ImmutableStringReference(decryptedStr2));
                            
                            mutableMethod.replaceInstruction(i, newConstStr2);
                            mutableMethod.removeInstruction(i + 1);
                            modified = true;
                            this.decryptedCount++;
                        }
                    }
                }
            }
        }
        return modified ? mutableMethod : methodImpl;
    }
}