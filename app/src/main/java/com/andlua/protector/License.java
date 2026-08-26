package com.andlua.protector;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Calendar;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class License {
    static final String PASTE = "https://pastebin.com/raw/k4ZPLGUj";
    private static final Pattern DATE =
            Pattern.compile("(\\d{4})[/.-](\\d{1,2})[/.-](\\d{1,2})");

    private License() {}

    static void requireValid() throws Exception {
        String body = fetchTimed(4000);
        if (body == null || body.length() == 0) {
            return;
        }
        int[] ymd = parse(body);
        if (ymd == null) {
            return;
        }
        if (isPast(ymd[0], ymd[1], ymd[2])) {
            throw new IllegalStateException("expired");
        }
    }

    private static String fetchTimed(final int ms) {
        final String[] box = new String[1];
        Thread t = new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    box[0] = fetch();
                } catch (Throwable ignored) {
                }
            }
        }, "alp-license");
        t.start();
        try {
            t.join(ms);
        } catch (InterruptedException ignored) {
        }
        return box[0];
    }

    private static String fetch() throws Exception {
        HttpURLConnection conn = (HttpURLConnection) new URL(PASTE).openConnection();
        try {
            conn.setConnectTimeout(2500);
            conn.setReadTimeout(2500);
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
                if (total > 512) {
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
        if (!m.find()) {
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
}
