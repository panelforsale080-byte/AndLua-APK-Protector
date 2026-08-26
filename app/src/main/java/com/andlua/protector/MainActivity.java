package com.andlua.protector;

import android.Manifest;
import android.animation.ObjectAnimator;
import android.animation.ValueAnimator;
import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.os.Handler;
import android.os.Looper;
import android.provider.Settings;
import android.view.View;
import android.view.animation.AccelerateDecelerateInterpolator;
import android.view.animation.DecelerateInterpolator;
import android.widget.Button;
import android.widget.ImageView;
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
    private static final int REQ_MANAGE = 44;
    private static final int REQ_WRITE = 45;
    private static final int STEP_MS = 900;

    private final Handler main = new Handler(Looper.getMainLooper());
    private Uri picked;
    private File lastProtected;
    private String lastOutName = "sealed.apk";

    private TextView status;
    private TextView logView;
    private TextView title;
    private Button protectBtn;
    private Button pickBtn;
    private ProgressBar progress;
    private ImageView logo;
    private View hero;
    private View socialRow;

    private boolean workDone;
    private Exception workError;
    private int stepIndex;
    private boolean sealing;
    private boolean pendingSave;

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);
        status = findViewById(R.id.status);
        logView = findViewById(R.id.log);
        title = findViewById(R.id.title);
        protectBtn = findViewById(R.id.btn_protect);
        pickBtn = findViewById(R.id.btn_pick);
        progress = findViewById(R.id.progress);
        logo = findViewById(R.id.logo);
        hero = findViewById(R.id.hero);
        socialRow = findViewById(R.id.social_row);

        playEnter();
        pulse(logo);

        findViewById(R.id.btn_telegram).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                openUrl("https://t.me/axcelLOki");
            }
        });
        findViewById(R.id.btn_youtube).setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                openUrl("https://www.youtube.com/@AtoomsBm");
            }
        });

        pickBtn.setOnClickListener(new View.OnClickListener() {
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
                    toast(getString(R.string.need_pick));
                    return;
                }
                runProtect();
            }
        });
    }

    private void playEnter() {
        hero.setAlpha(0f);
        hero.setTranslationY(40f);
        hero.animate().alpha(1f).translationY(0f).setDuration(700)
                .setInterpolator(new DecelerateInterpolator()).start();
        socialRow.setAlpha(0f);
        socialRow.animate().alpha(1f).setStartDelay(280).setDuration(600).start();
        title.setAlpha(0f);
        title.animate().alpha(1f).setStartDelay(160).setDuration(650).start();
    }

    private void pulse(View view) {
        ObjectAnimator sx = ObjectAnimator.ofFloat(view, View.SCALE_X, 1f, 1.07f, 1f);
        ObjectAnimator sy = ObjectAnimator.ofFloat(view, View.SCALE_Y, 1f, 1.07f, 1f);
        sx.setDuration(2200);
        sy.setDuration(2200);
        sx.setRepeatCount(ValueAnimator.INFINITE);
        sy.setRepeatCount(ValueAnimator.INFINITE);
        sx.setInterpolator(new AccelerateDecelerateInterpolator());
        sy.setInterpolator(new AccelerateDecelerateInterpolator());
        sx.start();
        sy.start();
    }

    private void runProtect() {
        if (sealing) {
            return;
        }
        sealing = true;
        workDone = false;
        workError = null;
        stepIndex = 0;
        pendingSave = false;
        setBusy(true);
        logView.setText("");
        progress.setProgress(0);
        status.setText(getString(R.string.working));
        startSealWork();
        playNextStep();
    }

    private void startSealWork() {
        new Thread(new Runnable() {
            @Override
            public void run() {
                try {
                    File inFile = new File(getCacheDir(), "input.apk");
                    copyUri(picked, inFile);
                    lastOutName = guessName(picked, "package") + "_sealed.apk";
                    File outFile = new File(getCacheDir(), lastOutName);
                    ProtectEngine.protect(MainActivity.this, inFile, outFile);
                    lastProtected = outFile;
                    workDone = true;
                } catch (Exception e) {
                    workError = e;
                    workDone = true;
                }
            }
        }).start();
    }

    private void playNextStep() {
        final String[] steps = getResources().getStringArray(R.array.seal_steps);
        if (stepIndex < steps.length) {
            final String line = steps[stepIndex];
            logView.append("▸  " + line + "\n");
            status.setText(line);
            int pct = (int) ((stepIndex + 1) * (100f / (steps.length + 1)));
            animateProgress(pct);
            flashStatus();
            stepIndex++;
            main.postDelayed(new Runnable() {
                @Override
                public void run() {
                    playNextStep();
                }
            }, STEP_MS);
            return;
        }
        waitForWork();
    }

    private void waitForWork() {
        if (!workDone) {
            status.setText(getString(R.string.finishing));
            main.postDelayed(new Runnable() {
                @Override
                public void run() {
                    waitForWork();
                }
            }, 400);
            return;
        }
        if (workError != null) {
            setBusy(false);
            sealing = false;
            status.setText(getString(R.string.failed));
            logView.append("▸  " + getString(R.string.failed) + "\n");
            toast(getString(R.string.failed));
            return;
        }
        animateProgress(100);
        status.setText(getString(R.string.ready));
        logView.append("▸  " + getString(R.string.ready) + "\n");
        setBusy(false);
        sealing = false;
        askSave();
    }

    private void askSave() {
        new AlertDialog.Builder(this)
                .setTitle(R.string.save_title)
                .setMessage(R.string.save_message)
                .setCancelable(true)
                .setPositiveButton(R.string.save_yes, new android.content.DialogInterface.OnClickListener() {
                    @Override
                    public void onClick(android.content.DialogInterface dialog, int which) {
                        saveToSdcard();
                    }
                })
                .setNegativeButton(R.string.save_no, null)
                .show();
    }

    private void saveToSdcard() {
        if (lastProtected == null || !lastProtected.exists()) {
            toast(getString(R.string.failed));
            return;
        }
        if (Build.VERSION.SDK_INT >= 30) {
            if (!Environment.isExternalStorageManager()) {
                pendingSave = true;
                try {
                    Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                    intent.setData(Uri.parse("package:" + getPackageName()));
                    startActivityForResult(intent, REQ_MANAGE);
                } catch (Exception e) {
                    Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                    startActivityForResult(intent, REQ_MANAGE);
                }
                toast(getString(R.string.need_storage));
                return;
            }
        } else if (Build.VERSION.SDK_INT >= 23) {
            if (checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE)
                    != PackageManager.PERMISSION_GRANTED) {
                pendingSave = true;
                requestPermissions(new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE}, REQ_WRITE);
                return;
            }
        }
        writeSdcard();
    }

    private void writeSdcard() {
        try {
            File dir = new File("/sdcard");
            if (!dir.exists() || !dir.canWrite()) {
                File ext = Environment.getExternalStorageDirectory();
                if (ext != null) {
                    dir = ext;
                }
            }
            if (!dir.exists()) {
                dir.mkdirs();
            }
            File dest = new File(dir, lastOutName);
            copyFile(lastProtected, dest);
            status.setText(getString(R.string.saved, dest.getAbsolutePath()));
            toast(getString(R.string.saved, dest.getAbsolutePath()));
        } catch (Exception e) {
            status.setText(getString(R.string.save_fail));
            toast(getString(R.string.save_fail));
        }
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] grantResults) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults);
        if (requestCode == REQ_WRITE && pendingSave) {
            pendingSave = false;
            if (grantResults.length > 0 && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                writeSdcard();
            } else {
                toast(getString(R.string.need_storage));
            }
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_MANAGE && pendingSave) {
            pendingSave = false;
            if (Build.VERSION.SDK_INT < 30 || Environment.isExternalStorageManager()) {
                writeSdcard();
            } else {
                toast(getString(R.string.need_storage));
            }
            return;
        }
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
            lastProtected = null;
            status.setText(getString(R.string.selected));
            logView.setText(getString(R.string.ready_hint) + "\n");
            protectBtn.animate().scaleX(1.04f).scaleY(1.04f).setDuration(180)
                    .withEndAction(new Runnable() {
                        @Override
                        public void run() {
                            protectBtn.animate().scaleX(1f).scaleY(1f).setDuration(180).start();
                        }
                    }).start();
        }
    }

    private void flashStatus() {
        status.setAlpha(0.35f);
        status.animate().alpha(1f).setDuration(320).start();
    }

    private void animateProgress(int to) {
        ObjectAnimator.ofInt(progress, "progress", progress.getProgress(), to)
                .setDuration(520)
                .start();
    }

    private void openUrl(String url) {
        try {
            startActivity(new Intent(Intent.ACTION_VIEW, Uri.parse(url)));
        } catch (Exception e) {
            toast(url);
        }
    }

    private void copyUri(Uri uri, File dest) throws Exception {
        InputStream in = getContentResolver().openInputStream(uri);
        if (in == null) {
            throw new IllegalStateException("closed");
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

    private static void copyFile(File src, File dest) throws Exception {
        InputStream in = new FileInputStream(src);
        try {
            OutputStream out = new FileOutputStream(dest);
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
        progress.setVisibility(View.VISIBLE);
        protectBtn.setEnabled(!busy && picked != null);
        pickBtn.setEnabled(!busy);
    }

    private void toast(String msg) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show();
    }
}
