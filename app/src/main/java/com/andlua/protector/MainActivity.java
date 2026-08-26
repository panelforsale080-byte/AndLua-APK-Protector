package com.andlua.protector;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.view.View;
import android.widget.Button;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;

public class MainActivity extends Activity {
    private static final int REQ_PICK = 41;
    private static final int REQ_SAVE = 42;

    private final Handler main = new Handler(Looper.getMainLooper());
    private Uri picked;
    private File lastProtected;
    private String lastOutName = "protected.apk";

    private TextView status;
    private TextView logView;
    private Button protectBtn;
    private Button saveBtn;
    private ProgressBar progress;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        status = findViewById(R.id.status);
        logView = findViewById(R.id.log);
        protectBtn = findViewById(R.id.btn_protect);
        saveBtn = findViewById(R.id.btn_save);
        progress = findViewById(R.id.progress);

        findViewById(R.id.btn_pick).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("application/vnd.android.package-archive");
                intent.putExtra(Intent.EXTRA_MIME_TYPES, new String[]{
                        "application/vnd.android.package-archive",
                        "application/octet-stream",
                        "*/*"
                });
                startActivityForResult(intent, REQ_PICK);
            }
        });

        protectBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (picked == null) {
                    toast("Select an APK first");
                    return;
                }
                runProtect();
            }
        });

        saveBtn.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                if (lastProtected == null || !lastProtected.exists()) {
                    toast("Protect an APK first");
                    return;
                }
                Intent intent = new Intent(Intent.ACTION_CREATE_DOCUMENT);
                intent.addCategory(Intent.CATEGORY_OPENABLE);
                intent.setType("application/vnd.android.package-archive");
                intent.putExtra(Intent.EXTRA_TITLE, lastOutName);
                startActivityForResult(intent, REQ_SAVE);
            }
        });
    }

    private void runProtect() {
        setBusy(true);
        logView.setText("");
        status.setText("Protecting…");
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    File inFile = new File(getCacheDir(), "input.apk");
                    copyUri(picked, inFile);
                    lastOutName = guessName(picked, "app") + "_protected.apk";
                    File outFile = new File(getExternalFilesDir(null), lastOutName);
                    if (outFile.getParentFile() != null) {
                        outFile.getParentFile().mkdirs();
                    }
                    ProtectEngine.protect(MainActivity.this, inFile, outFile, new ProtectEngine.Log() {
                        @Override
                        public void line(final String msg) {
                            main.post(new Runnable() {
                                @Override
                                public void run() {
                                    logView.append(msg + "\n");
                                }
                            });
                        }
                    });
                    lastProtected = outFile;
                    main.post(new Runnable() {
                        @Override
                        public void run() {
                            setBusy(false);
                            status.setText("Protected. Save the APK.");
                            saveBtn.setEnabled(true);
                            toast("Protected " + lastOutName);
                        }
                    });
                } catch (final Exception e) {
                    main.post(new Runnable() {
                        @Override
                        public void run() {
                            setBusy(false);
                            status.setText("Failed");
                            logView.append("ERROR: " + e + "\n");
                            toast(String.valueOf(e.getMessage()));
                        }
                    });
                }
            }
        }).start();
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) {
            return;
        }
        if (requestCode == REQ_PICK) {
            picked = data.getData();
            try {
                getContentResolver().takePersistableUriPermission(picked, Intent.FLAG_GRANT_READ_URI_PERMISSION);
            } catch (SecurityException ignored) {
            }
            protectBtn.setEnabled(true);
            saveBtn.setEnabled(false);
            lastProtected = null;
            status.setText("Selected: " + picked.getLastPathSegment());
            logView.setText("Ready. Tap Protect.\nOnly assets/*.lua are wrapped. Original AndLua encryption stays as the inner layer.\n");
        } else if (requestCode == REQ_SAVE) {
            Uri dest = data.getData();
            try {
                copyFileToUri(lastProtected, dest);
                status.setText("Saved.");
                toast("Saved protected APK");
            } catch (Exception e) {
                status.setText("Save failed");
                logView.append("SAVE ERROR: " + e + "\n");
            }
        }
    }

    private void copyUri(Uri uri, File dest) throws Exception {
        InputStream in = getContentResolver().openInputStream(uri);
        if (in == null) {
            throw new IllegalStateException("cannot open selected APK");
        }
        try {
            FileOutputStream out = new FileOutputStream(dest);
            try {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
            } finally {
                out.close();
            }
        } finally {
            in.close();
        }
    }

    private void copyFileToUri(File src, Uri dest) throws Exception {
        InputStream in = new FileInputStream(src);
        try {
            OutputStream out = getContentResolver().openOutputStream(dest);
            if (out == null) {
                throw new IllegalStateException("cannot open save destination");
            }
            try {
                byte[] buf = new byte[8192];
                int n;
                while ((n = in.read(buf)) != -1) {
                    out.write(buf, 0, n);
                }
            } finally {
                out.close();
            }
        } finally {
            in.close();
        }
    }

    private static String guessName(Uri uri, String fallback) {
        String seg = uri.getLastPathSegment();
        if (seg == null || seg.trim().isEmpty()) {
            return fallback;
        }
        int slash = Math.max(seg.lastIndexOf('/'), seg.lastIndexOf(':'));
        if (slash >= 0 && slash < seg.length() - 1) {
            seg = seg.substring(slash + 1);
        }
        if (seg.toLowerCase().endsWith(".apk")) {
            seg = seg.substring(0, seg.length() - 4);
        }
        return seg;
    }

    private void setBusy(boolean busy) {
        progress.setVisibility(busy ? View.VISIBLE : View.GONE);
        protectBtn.setEnabled(!busy && picked != null);
        findViewById(R.id.btn_pick).setEnabled(!busy);
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }
}
