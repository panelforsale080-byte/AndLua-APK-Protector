package com.andlua.protector;

import android.content.Context;

import com.android.apksig.ApkSigner;

import java.io.File;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.Collections;

final class Signer {
    private static final String ASSET = "signing.p12";
    private static final String ALIAS = "alp";
    private static final char[] PASS = "andlua-protect".toCharArray();

    private Signer() {}

    static void sign(Context ctx, File input, File output) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        InputStream in = ctx.getAssets().open(ASSET);
        try {
            ks.load(in, PASS);
        } finally {
            in.close();
        }
        PrivateKey key = (PrivateKey) ks.getKey(ALIAS, PASS);
        X509Certificate cert = (X509Certificate) ks.getCertificate(ALIAS);
        if (key == null || cert == null) {
            throw new IllegalStateException("signing.p12 missing alp key");
        }
        ApkSigner.SignerConfig config = new ApkSigner.SignerConfig.Builder(
                "alp", key, Collections.singletonList(cert)).build();
        new ApkSigner.Builder(Collections.singletonList(config))
                .setInputApk(input)
                .setOutputApk(output)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .setMinSdkVersion(21)
                .build()
                .sign();
    }
}
