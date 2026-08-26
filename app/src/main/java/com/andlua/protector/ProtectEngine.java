package com.andlua.protector;

import android.content.Context;

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
    static final String SA = "9F3C1A7E0B24D865E1A90C47B2F6583D";
    static final String SB = "C0A18B47D2E659F301847A5C9B3E12D6";
    static final String LC = "AXL_LCH_SLOT_v1_QQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQQ";

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

            byte[] master = AesLayer.randomKey();
            byte[] certDer = Signer.certDer(ctx);
            byte[] material = AesLayer.xor(master, AesLayer.bindMask(pkg, certDer));
            stubDex = patchDex(stubDex, material, originalLauncher);

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
                byte[] wrapped = AesLayer.wrap(master, raw);
                apk.removeInputSource(path);
                apk.add(new ByteInputSource(wrapped, path));
            }

            stripSignatures(apk);
            apk.removeInputSource("assets/alpprotect.key");
            apk.removeInputSource("assets/alpprotect.launcher");
            injectRuntimeDex(apk, stubDex);

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

    private static byte[] patchDex(byte[] dex, byte[] material, String launcher) {
        if (material.length != 32) {
            throw new IllegalStateException("This package cannot be sealed");
        }
        byte[] a = toHex(material, 0, 16).getBytes(StandardCharsets.US_ASCII);
        byte[] b = toHex(material, 16, 16).getBytes(StandardCharsets.US_ASCII);
        byte[] out = dex;
        out = replaceOnce(out, SA.getBytes(StandardCharsets.US_ASCII), a);
        out = replaceOnce(out, SB.getBytes(StandardCharsets.US_ASCII), b);
        out = replaceOnce(out, LC.getBytes(StandardCharsets.US_ASCII), padAscii(launcher, LC.length()));
        return out;
    }

    private static byte[] replaceOnce(byte[] hay, byte[] needle, byte[] repl) {
        if (needle.length != repl.length) {
            throw new IllegalStateException("This package cannot be sealed");
        }
        int at = indexOf(hay, needle);
        if (at < 0) {
            throw new IllegalStateException("This package cannot be sealed");
        }
        if (indexOfFrom(hay, needle, at + 1) >= 0) {
            throw new IllegalStateException("This package cannot be sealed");
        }
        byte[] out = new byte[hay.length];
        System.arraycopy(hay, 0, out, 0, hay.length);
        System.arraycopy(repl, 0, out, at, repl.length);
        return out;
    }

    private static byte[] padAscii(String value, int len) {
        String trimmed = value.length() > len ? value.substring(0, len) : value;
        StringBuilder sb = new StringBuilder(len);
        sb.append(trimmed);
        while (sb.length() < len) {
            sb.append(' ');
        }
        return sb.toString().getBytes(StandardCharsets.US_ASCII);
    }

    private static String toHex(byte[] data, int off, int len) {
        StringBuilder sb = new StringBuilder(len * 2);
        for (int i = 0; i < len; i++) {
            sb.append(String.format("%02X", data[off + i] & 0xff));
        }
        return sb.toString();
    }

    private static int indexOf(byte[] data, byte[] needle) {
        return indexOfFrom(data, needle, 0);
    }

    private static int indexOfFrom(byte[] data, byte[] needle, int start) {
        outer:
        for (int i = start; i <= data.length - needle.length; i++) {
            for (int j = 0; j < needle.length; j++) {
                if (data[i + j] != needle[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
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
