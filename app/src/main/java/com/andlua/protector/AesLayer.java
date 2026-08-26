package com.andlua.protector;

import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class AesLayer {
    static final byte[] MAGIC = new byte[]{'A', 'L', 'P', '2'};
    private static final int VERSION = 1;
    private static final int NONCE_LEN = 12;
    private static final int TAG_BITS = 128;

    private AesLayer() {}

    static boolean isWrapped(byte[] data) {
        if (data == null || data.length < 4 + 1 + NONCE_LEN + 16) {
            return false;
        }
        return data[0] == MAGIC[0]
                && data[1] == MAGIC[1]
                && data[2] == MAGIC[2]
                && data[3] == MAGIC[3];
    }

    static byte[] randomKey() {
        byte[] key = new byte[32];
        new SecureRandom().nextBytes(key);
        return key;
    }

    static byte[] wrap(byte[] key, byte[] plaintext) throws Exception {
        byte[] nonce = new byte[NONCE_LEN];
        new SecureRandom().nextBytes(nonce);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        byte[] ct = cipher.doFinal(plaintext);
        ByteBuffer buf = ByteBuffer.allocate(MAGIC.length + 1 + nonce.length + ct.length);
        buf.put(MAGIC);
        buf.put((byte) VERSION);
        buf.put(nonce);
        buf.put(ct);
        return buf.array();
    }

    static byte[] deriveStorageMask(String packageName) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update("ALP2-KEY-MASK-v1".getBytes("UTF-8"));
        sha.update(packageName.getBytes("UTF-8"));
        return sha.digest();
    }

    static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i % b.length]);
        }
        return out;
    }
}
