package com.alpprotect;

import android.util.Base64;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

final class AlpCrypto {
    static final byte[] MAGIC = new byte[]{'A', 'L', 'P', '2'};
    static final int VERSION = 1;
    static final int NONCE_LEN = 12;
    static final int TAG_BITS = 128;

    private AlpCrypto() {}

    static boolean isWrapped(byte[] data) {
        if (data == null || data.length < 4 + 1 + NONCE_LEN + 16) {
            return false;
        }
        return data[0] == MAGIC[0]
                && data[1] == MAGIC[1]
                && data[2] == MAGIC[2]
                && data[3] == MAGIC[3];
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

    static byte[] unwrap(byte[] key, byte[] blob) throws Exception {
        if (!isWrapped(blob)) {
            return blob;
        }
        ByteBuffer buf = ByteBuffer.wrap(blob);
        buf.position(MAGIC.length);
        int version = buf.get() & 0xff;
        if (version != VERSION) {
            throw new IllegalStateException("unsupported ALP wrapper version " + version);
        }
        byte[] nonce = new byte[NONCE_LEN];
        buf.get(nonce);
        byte[] ct = new byte[buf.remaining()];
        buf.get(ct);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"),
                new GCMParameterSpec(TAG_BITS, nonce));
        return cipher.doFinal(ct);
    }

    static byte[] deriveStorageMask(String packageName) throws Exception {
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        sha.update("ALP2-KEY-MASK-v1".getBytes(StandardCharsets.UTF_8));
        sha.update(packageName.getBytes(StandardCharsets.UTF_8));
        return sha.digest();
    }

    static byte[] xor(byte[] a, byte[] b) {
        byte[] out = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            out[i] = (byte) (a[i] ^ b[i % b.length]);
        }
        return out;
    }

    static String encodeKey(byte[] rawKey, String packageName) throws Exception {
        byte[] masked = xor(rawKey, deriveStorageMask(packageName));
        return Base64.encodeToString(masked, Base64.NO_WRAP);
    }

    static byte[] decodeKey(String encoded, String packageName) throws Exception {
        byte[] masked = Base64.decode(encoded, Base64.NO_WRAP);
        return xor(masked, deriveStorageMask(packageName));
    }
}
