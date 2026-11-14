package com.andlua.protector;

import android.app.Activity;
import android.content.Context;
import android.graphics.Typeface;
import android.view.View;
import android.view.ViewGroup;
import android.widget.TextView;

final class Pixel {
    private static Typeface face;

    private Pixel() {}

    static void paint(Activity activity) {
        paint(activity.findViewById(android.R.id.content));
    }

    static void paint(View view) {
        if (view == null) {
            return;
        }
        if (view instanceof TextView) {
            TextView text = (TextView) view;
            text.setTypeface(face(view.getContext()));
        }
        if (view instanceof ViewGroup) {
            ViewGroup group = (ViewGroup) view;
            for (int i = 0; i < group.getChildCount(); i++) {
                paint(group.getChildAt(i));
            }
        }
    }

    static Typeface face(Context context) {
        if (face == null) {
            face = Typeface.createFromAsset(context.getAssets(), "fonts/monocraft.ttf");
        }
        return face;
    }
}
