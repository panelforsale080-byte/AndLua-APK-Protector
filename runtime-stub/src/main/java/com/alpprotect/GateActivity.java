package com.alpprotect;

import android.app.Activity;
import android.content.Intent;
import android.graphics.Color;
import android.os.Bundle;
import android.widget.TextView;
import android.widget.Toast;

public class GateActivity extends Activity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        TextView view = new TextView(this);
        view.setTextColor(Color.WHITE);
        view.setBackgroundColor(Color.BLACK);
        view.setPadding(48, 48, 48, 48);
        view.setText("AndLua protector runtime…");
        setContentView(view);

        try {
            AlpRuntime.bootstrap(this);
            String launcher = AlpRuntime.originalLauncher(this);
            Intent intent = new Intent();
            intent.setClassName(getPackageName(), launcher);
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_ACTIVITY_CLEAR_TASK);
            startActivity(intent);
            finish();
        } catch (Exception e) {
            view.setText("Protect bootstrap failed:\n" + e);
            Toast.makeText(this, String.valueOf(e.getMessage()), Toast.LENGTH_LONG).show();
        }
    }
}
