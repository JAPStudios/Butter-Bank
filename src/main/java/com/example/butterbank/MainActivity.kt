package com.example.butterbank

import android.app.Activity
import android.os.Bundle
import android.view.Gravity
import android.widget.LinearLayout
import android.widget.TextView

class MainActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(32, 32, 32, 32)
        }
        content.addView(TextView(this).apply {
            text = "BUTTER BANK"
            textSize = 28f
            gravity = Gravity.CENTER
            setTextColor(0xFF244B35.toInt())
        })
        content.addView(TextView(this).apply {
            text = "Banking services are not connected yet. This prototype does not open accounts, hold deposits, or process payments."
            textSize = 16f
            gravity = Gravity.CENTER
            setPadding(0, 20, 0, 0)
        })
        setContentView(content)
    }
}
