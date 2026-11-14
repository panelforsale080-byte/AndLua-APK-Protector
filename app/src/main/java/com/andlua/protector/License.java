package com.andlua.protector;

import android.util.Base64;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.Arrays;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.NoRouteToHostException;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Calendar;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class License {
    static final String OFFLINE = "offline";
    static final String EXPIRED = "expired";
    private static final Pattern DATE =
            Pattern.compile("(\\d{4})[/.-](\\d{1,2})[/.-](\\d{1,2})");

    private License() {}

    static void requireValid() throws Exception {
        Fetch fetched = fetchTimed(6000);
        if (fetched.offline) {
            throw new IllegalStateException(OFFLINE);
        }
        if (fetched.body == null || fetched.body.length() == 0) {
            throw new IllegalStateException(EXPIRED);
        }
        String dateLine = null;
        String sigLine = null;
        String[] lines = fetched.body.split("\\r?\\n");
        for (String line : lines) {
            String trimmed = line.trim();
            if (trimmed.length() == 0) {
                continue;
            }
            if (DATE.matcher(trimmed).matches()) {
                dateLine = trimmed;
            } else {
                sigLine = trimmed;
            }
        }
        if (dateLine == null || sigLine == null || !verify(dateLine, sigLine)) {
            throw new IllegalStateException(EXPIRED);
        }
        int[] ymd = parse(dateLine);
        if (ymd == null || isPast(ymd[0], ymd[1], ymd[2])) {
            throw new IllegalStateException(EXPIRED);
        }
    }

    private static boolean verify(String dateLine, String sigLine) {
        try {
            byte[] pub = Base64.decode(Sealed.publicKey(), Base64.DEFAULT);
            PublicKey key = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(pub));
            Signature sig = Signature.getInstance("SHA256withRSA");
            sig.initVerify(key);
            sig.update(dateLine.getBytes(StandardCharsets.UTF_8));
            return sig.verify(Base64.decode(sigLine, Base64.DEFAULT));
        } catch (Exception e) {
            return false;
        }
    }

    private static final class Fetch {
        String body;
        boolean offline;
    }

    private static Fetch fetchTimed(final int ms) {
        final Fetch fetched = new Fetch();
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    fetched.body = fetch();
                } catch (Throwable e) {
                    fetched.offline = isOffline(e);
                }
            }
        }, "alp-license");
        t.start();
        try {
            t.join(ms);
        } catch (InterruptedException ignored) {
            fetched.offline = true;
        }
        if (t.isAlive()) {
            fetched.offline = true;
            t.interrupt();
        }
        return fetched;
    }

    private static boolean isOffline(Throwable e) {
        while (e != null) {
            if (e instanceof UnknownHostException
                    || e instanceof SocketTimeoutException
                    || e instanceof ConnectException
                    || e instanceof NoRouteToHostException
                    || e instanceof SocketException) {
                return true;
            }
            e = e.getCause();
        }
        return false;
    }

    private static String fetch() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(Sealed.endpoint()).openConnection();
        try {
            conn.setConnectTimeout(4000);
            conn.setReadTimeout(4000);
            conn.setUseCaches(false);
            conn.setInstanceFollowRedirects(true);
            conn.setRequestProperty("User-Agent",
                    "Mozilla/5.0 (Linux; Android 13) AppleWebKit/537.36 Chrome/120.0.0.0 Mobile Safari/537.36");
            conn.connect();
            if (conn.getResponseCode() != 200) {
                return null;
            }
            InputStream in = conn.getInputStream();
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buf = new byte[256];
            int n;
            int total = 0;
            while ((n = in.read(buf)) != -1) {
                out.write(buf, 0, n);
                total += n;
                if (total > 2048) {
                    break;
                }
            }
            in.close();
            return new String(out.toByteArray(), StandardCharsets.UTF_8).trim();
        } finally {
            conn.disconnect();
        }
    }

    private static int[] parse(String body) {
        if (body == null) {
            return null;
        }
        Matcher m = DATE.matcher(body);
        if (!m.matches()) {
            return null;
        }
        int y = Integer.parseInt(m.group(1));
        int mo = Integer.parseInt(m.group(2));
        int d = Integer.parseInt(m.group(3));
        if (y < 2020 || mo < 1 || mo > 12 || d < 1 || d > 31) {
            return null;
        }
        return new int[]{y, mo, d};
    }

    private static boolean isPast(int y, int mo, int d) {
        Calendar now = Calendar.getInstance();
        int cy = now.get(Calendar.YEAR);
        int cm = now.get(Calendar.MONTH) + 1;
        int cd = now.get(Calendar.DAY_OF_MONTH);
        if (cy != y) {
            return cy > y;
        }
        if (cm != mo) {
            return cm > mo;
        }
        return cd > d;
    }

    /** Address and verifier material. Stored as a rolling mix, not as text. */
    private static final class Sealed {
        private static final int[] A0 = {
            60, 203, 127, 176, 97, 28, 61, 255, 249, 123, 112, 175,
            125, 16, 127, 51, 142, 165, 215, 16, 241, 119, 145, 50,
            89, 33
        };

        private static final int[] A1 = {
            54, 2, 213, 56, 165, 56, 246, 69, 33, 212, 6, 160,
            174, 41, 90, 160, 222, 88, 205, 21, 48, 177, 170, 216,
            236, 228, 222
        };

        private static final int[] A2 = {
            202, 181, 78, 166, 122, 156, 158, 2, 129, 200, 51, 171,
            85, 117, 213, 34, 39, 15, 15, 141, 30, 193, 101, 35,
            240, 25, 249
        };

        private static final int[] B0 = {
            25, 246, 66, 130, 91, 76, 83, 158, 201, 125, 108, 240,
            114, 18, 98, 28, 194, 176, 146, 33, 213, 84, 183, 27,
            118, 20, 28, 47, 224, 71, 254, 22, 214, 35, 41, 238,
            38, 162, 137, 26, 116, 150, 242, 40, 194, 118, 112, 145,
            243, 146, 170, 201, 253, 253, 232, 74, 144, 79, 187, 189,
            57, 162, 202, 118, 175, 66, 66, 242, 5, 43, 80, 52,
            164, 48, 203, 101, 15, 195, 36, 244, 83, 54, 149, 49,
            219, 121, 215, 107, 18, 129, 68, 96, 248, 52, 22, 100,
            103, 148, 150, 50, 152, 222, 180, 104, 57, 168, 221, 217,
            37, 211, 105, 81, 122, 46, 137, 192, 182, 38, 162, 244,
            117, 153, 183, 225, 41, 238, 49, 199, 178, 36
        };

        private static final int[] B1 = {
            61, 231, 70, 11, 12, 239, 5, 2, 35, 217, 18, 17,
            79, 140, 47, 230, 136, 204, 228, 223, 27, 54, 22, 116,
            187, 80, 153, 112, 210, 185, 240, 53, 134, 195, 151, 87,
            108, 103, 168, 240, 90, 41, 112, 64, 11, 192, 132, 215,
            16, 214, 1, 7, 225, 248, 41, 184, 79, 50, 240, 14,
            103, 229, 240, 46, 237, 153, 222, 107, 238, 16, 80, 114,
            145, 143, 39, 13, 40, 249, 224, 123, 122, 110, 171, 118,
            8, 174, 237, 205, 119, 51, 60, 226, 231, 240, 40, 53,
            136, 91, 175, 186, 110, 207, 202, 154, 239, 2, 165, 211,
            250, 13, 145, 210, 0, 46, 167, 83, 212, 253, 162, 155,
            240, 149, 237, 219, 191, 116, 29, 232, 240, 201, 246
        };

        private static final int[] B2 = {
            13, 152, 194, 103, 88, 1, 216, 1, 188, 37, 208, 72,
            193, 161, 216, 203, 65, 155, 66, 131, 231, 228, 209, 57,
            204, 92, 240, 46, 142, 67, 15, 186, 228, 148, 195, 27,
            105, 8, 171, 96, 97, 36, 249, 125, 15, 15, 211, 82,
            96, 47, 96, 213, 27, 255, 42, 200, 28, 103, 235, 231,
            26, 32, 243, 215, 179, 15, 106, 97, 31, 109, 244, 176,
            118, 111, 172, 31, 47, 169, 51, 192, 83, 164, 111, 220,
            217, 52, 143, 49, 230, 14, 9, 49, 120, 229, 2, 188,
            44, 84, 112, 17, 250, 72, 53, 70, 134, 229, 210, 82,
            26, 70, 231, 52, 244, 223, 12, 137, 113, 44, 1, 94,
            242, 104, 161, 183, 29, 61, 115, 43, 90, 143, 61
        };

        private Sealed() {}

        static String endpoint() {
            return open(A0, A1, A2);
        }

        static String publicKey() {
            return open(B0, B1, B2);
        }

        private static String open(int[] a, int[] b, int[] c) {
            char[] out = new char[a.length + b.length + c.length];
            int at = 0;
            int state = 0x5A17C3E1;
            int[][] parts = new int[][] {a, b, c};
            for (int p = 0; p < parts.length; p++) {
                int[] part = parts[p];
                for (int i = 0; i < part.length; i++) {
                    state = mix(state);
                    out[at++] = (char) (part[i] ^ (state & 0xFF));
                }
            }
            String value = new String(out);
            Arrays.fill(out, '\0');
            return value;
        }

        private static int mix(int s) {
            s ^= s << 13;
            s ^= s >>> 17;
            s ^= s << 5;
            return s;
        }
    }
}
