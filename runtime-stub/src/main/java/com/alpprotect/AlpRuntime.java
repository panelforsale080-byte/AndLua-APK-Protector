package com.alpprotect;

import android.content.Context;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Enumeration;
import java.util.zip.ZipEntry;
import java.util.zip.ZipFile;

final class AlpRuntime {
    static final String KEY_ASSET = "alpprotect.key";
    static final String LAUNCHER_ASSET = "alpprotect.launcher";
    static final String MARKER = "alpprotect.ready";

    private AlpRuntime() {}

    static String originalLauncher(Context ctx) throws Exception {
        return new String(readAsset(ctx, LAUNCHER_ASSET), StandardCharsets.UTF_8).trim();
    }

    static void bootstrap(Context ctx) throws Exception {
        File marker = new File(ctx.getFilesDir(), MARKER);
        String pkg = ctx.getPackageName();
        byte[] key = AlpCrypto.decodeKey(
                new String(readAsset(ctx, KEY_ASSET), StandardCharsets.UTF_8).trim(), pkg);

        File luaMdDir = ctx.getDir("lua", Context.MODE_PRIVATE);
        File filesDir = ctx.getFilesDir();

        try (ZipFile zip = new ZipFile(ctx.getApplicationInfo().sourceDir)) {
            Enumeration<? extends ZipEntry> entries = zip.entries();
            while (entries.hasMoreElements()) {
                ZipEntry entry = entries.nextElement();
                if (entry.isDirectory()) {
                    continue;
                }
                String name = entry.getName();
                File dest = destFor(name, filesDir, luaMdDir);
                if (dest == null) {
                    continue;
                }
                File parent = dest.getParentFile();
                if (parent != null && !parent.exists() && !parent.mkdirs()) {
                    throw new IllegalStateException("cannot create " + parent);
                }
                byte[] data = readAll(zip.getInputStream(entry));
                if (name.startsWith("assets/") && name.toLowerCase().endsWith(".lua")
                        && AlpCrypto.isWrapped(data)) {
                    data = AlpCrypto.unwrap(key, data);
                }
                try (FileOutputStream out = new FileOutputStream(dest)) {
                    out.write(data);
                }
            }
        }

        PackageInfo pi = ctx.getPackageManager().getPackageInfo(pkg, 0);
        SharedPreferences info = ctx.getSharedPreferences("appInfo", Context.MODE_PRIVATE);
        info.edit()
                .putLong("lastUpdateTime", pi.lastUpdateTime)
                .putString("versionName", pi.versionName == null ? "" : pi.versionName)
                .apply();

        try (FileOutputStream out = new FileOutputStream(marker)) {
            out.write("ok".getBytes(StandardCharsets.UTF_8));
        }
    }

    private static File destFor(String name, File filesDir, File luaMdDir) {
        if (name.startsWith("assets/")) {
            String rel = name.substring("assets/".length());
            if (rel.isEmpty() || KEY_ASSET.equals(rel) || LAUNCHER_ASSET.equals(rel)) {
                return null;
            }
            return new File(filesDir, rel);
        }
        if (name.startsWith("lua/")) {
            String rel = name.substring("lua/".length());
            if (rel.isEmpty()) {
                return null;
            }
            return new File(luaMdDir, rel);
        }
        return null;
    }

    private static byte[] readAsset(Context ctx, String name) throws Exception {
        try (InputStream in = ctx.getAssets().open(name)) {
            return readAll(in);
        }
    }

    private static byte[] readAll(InputStream in) throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int n;
        while ((n = in.read(buf)) != -1) {
            out.write(buf, 0, n);
        }
        in.close();
        return out.toByteArray();
    }
}
