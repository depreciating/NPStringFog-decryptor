package com.npstringfog.decryptors;

import com.npstringfog.utils.CryptoUtils;
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
import org.jf.dexlib2.iface.instruction.formats.Instruction11x;
import org.jf.dexlib2.iface.instruction.formats.Instruction21c;
import org.jf.dexlib2.iface.reference.FieldReference;
import org.jf.dexlib2.iface.reference.MethodReference;
import org.jf.dexlib2.iface.reference.StringReference;
import org.jf.dexlib2.immutable.reference.ImmutableStringReference;

public class NPStringFog extends BaseDecryptor {
    private String dynamicKey = "npmanager";

    @Override
    protected void initialize(DexFile dexFile) {
        System.out.println("[*] Searching AST for dynamic key...");
        for (ClassDef classDef : dexFile.getClasses()) {
            if (classDef.getType().equals("Lobfuse/NPStringFog;")) {
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
                                            return;
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
        System.out.println("[-] Dynamic key not found in AST, using fallback: " + this.dynamicKey);
    }

    @Override
    protected MethodImplementation rewriteMethod(@Nonnull MethodImplementation methodImpl) {
        MutableMethodImplementation mutableMethod = new MutableMethodImplementation(methodImpl);
        boolean modified = false;

        int i = 0;
        while (i < mutableMethod.getInstructions().size() - 1) {
            Instruction current = mutableMethod.getInstructions().get(i);
            Instruction next = mutableMethod.getInstructions().get(i + 1);

            // Anchor directly onto the decode call instead of the string assignment
            if ((current.getOpcode() == Opcode.INVOKE_STATIC || current.getOpcode() == Opcode.INVOKE_STATIC_RANGE) &&
                next.getOpcode() == Opcode.MOVE_RESULT_OBJECT) {

                if (current instanceof ReferenceInstruction) {
                    ReferenceInstruction invokeInst = (ReferenceInstruction) current;
                    if (invokeInst.getReference() instanceof MethodReference) {
                        MethodReference targetMethod = (MethodReference) invokeInst.getReference();

                        if (targetMethod.getDefiningClass().contains("NPStringFog") && 
                            targetMethod.getName().equals("decode")) {
                            
                            int constStrIdx = -1;
                            String encryptedHex = null;

                            // Scan backwards (up to 10 instructions) to find the encrypted argument
                            for (int j = i - 1; j >= Math.max(0, i - 10); j--) {
                                Instruction prevInst = mutableMethod.getInstructions().get(j);
                                if (prevInst.getOpcode() == Opcode.CONST_STRING) {
                                    String possibleHex = ((StringReference) ((Instruction21c) prevInst).getReference()).getString();
                                    
                                    // Validate it's actually an encrypted hex string, ignoring dummy/empty strings
                                    if (possibleHex != null && possibleHex.length() >= 2 && 
                                        possibleHex.length() % 2 == 0 && possibleHex.matches("^[0-9A-Fa-f]+$")) {
                                        constStrIdx = j;
                                        encryptedHex = possibleHex;
                                        break; 
                                    }
                                }
                            }

                            // If we successfully traced the parameter back
                            if (encryptedHex != null) {
                                String decryptedStr = CryptoUtils.decryptXor(encryptedHex, this.dynamicKey);
                                if (decryptedStr != null) {
                                    int targetRegister = ((Instruction11x) next).getRegisterA();
                                    BuilderInstruction21c newConstStr = new BuilderInstruction21c(Opcode.CONST_STRING, targetRegister, new ImmutableStringReference(decryptedStr));
                                    
                                    // 1. Overwrite the MOVE_RESULT with the decrypted string
                                    mutableMethod.replaceInstruction(i + 1, newConstStr);
                                    // 2. Delete the INVOKE call
                                    mutableMethod.removeInstruction(i);
                                    // 3. Delete the original encrypted CONST_STRING assignment
                                    mutableMethod.removeInstruction(constStrIdx);
                                    
                                    modified = true;
                                    this.decryptedCount++;
                                    
                                    // Array indices shift after removal, 'continue' keeps the pointer properly aligned
                                    continue; 
                                }
                            }
                        }
                    }
                }
            }
            i++;
        }
        return modified ? mutableMethod : methodImpl;
    }
}