package com.andlua.protector;

import android.content.Context;
import android.util.Base64;

import com.reandroid.apk.ApkModule;
import com.reandroid.archive.ByteInputSource;
import com.reandroid.archive.InputSource;
import com.reandroid.arsc.chunk.xml.AndroidManifestBlock;
import com.reandroid.arsc.chunk.xml.ResXmlAttribute;
import com.reandroid.arsc.chunk.xml.ResXmlElement;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

final class ProtectEngine {
    static final String GATE = "com.alpprotect.GateActivity";
    static final String RUNTIME_DEX_ASSET = "alpprotect-runtime.dex";
    static final String KEY_ENTRY = "META-INF/androidx/emoji2/emoji2.version";
    static final String LAUNCHER_ENTRY = "META-INF/androidx/emoji2/emoji2-views.version";

    static File protect(Context ctx, File inputApk, File outputApk) throws Exception {
        License.requireValid();
        ApkModule apk = ApkModule.loadApkFile(inputApk);
        try {
            AndroidManifestBlock manifest = apk.getAndroidManifest();
            if (manifest == null) {
                throw new IllegalStateException("This package cannot be sealed");
            }
            String pkg = manifest.getPackageName();
            String originalLauncher = manifest.getMainActivityClassName();
            if (originalLauncher == null || originalLauncher.trim().isEmpty()) {
                throw new IllegalStateException("This package cannot be sealed");
            }

            byte[] stubDex = readAsset(ctx, RUNTIME_DEX_ASSET);
            if (stubDex.length < 64) {
                throw new IllegalStateException("This package cannot be sealed");
            }

            byte[] key = AesLayer.randomKey();
            String encodedKey = Base64.encodeToString(
                    AesLayer.xor(key, AesLayer.deriveStorageMask(pkg)), Base64.NO_WRAP);

            List<String> luaPaths = new ArrayList<>();
            for (InputSource src : apk.getInputSources()) {
                String name = src.getName();
                if (name != null && name.startsWith("assets/") && name.toLowerCase().endsWith(".lua")) {
                    luaPaths.add(name);
                }
            }
            if (luaPaths.isEmpty()) {
                throw new IllegalStateException("This package cannot be sealed");
            }

            for (String path : luaPaths) {
                InputSource src = apk.getInputSource(path);
                byte[] raw = readSource(src);
                if (AesLayer.isWrapped(raw)) {
                    continue;
                }
                byte[] wrapped = AesLayer.wrap(key, raw);
                apk.removeInputSource(path);
                apk.add(new ByteInputSource(wrapped, path));
            }

            stripSignatures(apk);
            injectRuntimeDex(apk, stubDex);

            apk.removeInputSource("assets/alpprotect.key");
            apk.removeInputSource("assets/alpprotect.launcher");
            apk.removeInputSource(KEY_ENTRY);
            apk.removeInputSource(LAUNCHER_ENTRY);
            apk.add(new ByteInputSource(encodedKey.getBytes(StandardCharsets.UTF_8), KEY_ENTRY));
            apk.add(new ByteInputSource(originalLauncher.getBytes(StandardCharsets.UTF_8), LAUNCHER_ENTRY));

            manifest.setMainActivityClassName(GATE);
            ResXmlElement original = manifest.getOrCreateActivity(originalLauncher, false);
            ResXmlAttribute exported = original.getOrCreateAndroidAttribute(
                    AndroidManifestBlock.NAME_exported, AndroidManifestBlock.ID_exported);
            exported.setValueAsBoolean(true);
            apk.refreshManifest();

            File unsigned = new File(ctx.getCacheDir(), "unsigned-" + outputApk.getName());
            if (unsigned.exists()) {
                unsigned.delete();
            }
            apk.writeApk(unsigned);
            Signer.sign(ctx, unsigned, outputApk);
            if (!unsigned.delete()) {
                unsigned.deleteOnExit();
            }
            return outputApk;
        } finally {
            apk.close();
        }
    }

    private static void injectRuntimeDex(ApkModule apk, byte[] stubDex) {
        int max = 0;
        for (InputSource src : apk.getInputSources()) {
            int n = InputSource.getDexNumber(src.getName());
            if (n > max) {
                max = n;
            }
        }
        int next = max <= 0 ? 2 : max + 1;
        String name = "classes" + next + ".dex";
        apk.removeInputSource(name);
        apk.add(new ByteInputSource(stubDex, name));
    }

    private static void stripSignatures(ApkModule apk) {
        apk.setApkSignatureBlock(null);
        List<String> remove = new ArrayList<>();
        for (InputSource src : apk.getInputSources()) {
            String name = src.getName();
            if (name == null) {
                continue;
            }
            String upper = name.toUpperCase();
            if (upper.startsWith("META-INF/") && (
                    upper.endsWith(".SF")
                            || upper.endsWith(".RSA")
                            || upper.endsWith(".DSA")
                            || upper.endsWith(".EC")
                            || upper.endsWith("MANIFEST.MF")
                            || upper.contains("SIG-"))) {
                remove.add(name);
            }
        }
        for (String name : remove) {
            apk.removeInputSource(name);
        }
    }

    private static byte[] readSource(InputSource src) throws Exception {
        InputStream in = src.openStream();
        try {
            return readAll(in);
        } finally {
            in.close();
        }
    }

    static byte[] readAsset(Context ctx, String name) throws Exception {
        InputStream in = ctx.getAssets().open(name);
        try {
            return readAll(in);
        } finally {
            in.close();
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        return out.toByteArray();
    }
}
