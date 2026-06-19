package com.npstringfog.decryptors;

import org.jf.dexlib2.DexFileFactory;
import org.jf.dexlib2.Opcodes;
import org.jf.dexlib2.iface.ClassDef;
import org.jf.dexlib2.iface.DexFile;
import org.jf.dexlib2.iface.Method;
import org.jf.dexlib2.iface.MethodImplementation;
import org.jf.dexlib2.rewriter.*;

import javax.annotation.Nonnull;
import java.io.File;
import java.util.ArrayList;
import java.util.List;

public abstract class BaseDecryptor {

    protected DexFile dexFile;
    protected int decryptedCount = 0;

    protected abstract void initialize(DexFile dexFile);
    protected abstract MethodImplementation rewriteMethod(@Nonnull MethodImplementation methodImpl);

    protected boolean shouldRemoveMethod(ClassDef classDef, Method method) {
        return false;
    }

    public void process(String inputPath, String outputPath) throws Exception {
        File inputFile = new File(inputPath);
        this.dexFile = DexFileFactory.loadDexFile(inputFile, Opcodes.getDefault());
        
        System.out.println("[*] Initializing decryptor state...");
        initialize(this.dexFile);

        System.out.println("[*] Patching instructions in memory...");
        
        DexRewriter rewriter = new DexRewriter(new RewriterModule() {
            @Nonnull
            @Override
            public Rewriter<ClassDef> getClassDefRewriter(@Nonnull Rewriters rewriters) {
                return new ClassDefRewriter(rewriters) {
                    @Nonnull
                    @Override
                    public ClassDef rewrite(@Nonnull ClassDef classDef) {
                        return new RewrittenClassDef(classDef) {
                            @Nonnull
                            @Override
                            public Iterable<? extends Method> getDirectMethods() {
                                return filterMethods(super.getDirectMethods(), classDef);
                            }

                            @Nonnull
                            @Override
                            public Iterable<? extends Method> getVirtualMethods() {
                                return filterMethods(super.getVirtualMethods(), classDef);
                            }

                            private Iterable<? extends Method> filterMethods(Iterable<? extends Method> methods, ClassDef classDef) {
                                List<Method> keptMethods = new ArrayList<>();
                                for (Method method : methods) {
                                    if (!shouldRemoveMethod(classDef, method)) {
                                        keptMethods.add(method);
                                    }
                                }
                                return keptMethods;
                            }
                        };
                    }
                };
            }

            @Nonnull
            @Override
            public Rewriter<MethodImplementation> getMethodImplementationRewriter(@Nonnull Rewriters rewriters) {
                return new MethodImplementationRewriter(rewriters) {
                    @Nonnull
                    @Override
                    public MethodImplementation rewrite(@Nonnull MethodImplementation methodImpl) {
                        return rewriteMethod(methodImpl);
                    }
                };
            }
        });

        DexFile rewrittenDex = rewriter.getDexFileRewriter().rewrite(this.dexFile);
        
        System.out.println("[*] Reassembling...");
        DexFileFactory.writeDexFile(outputPath, rewrittenDex);
        
        System.out.println("[+] Successfully patched " + decryptedCount + " strings!");
        System.out.println("[+] Saved to " + outputPath);
    }
}