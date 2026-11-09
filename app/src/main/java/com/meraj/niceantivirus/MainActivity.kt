package com.meraj.niceantivirus

import android.app.Activity
import android.os.Bundle
import android.widget.Button
import android.widget.LinearLayout
import android.widget.TextView
import android.graphics.Color
import android.view.Gravity
import android.view.ViewGroup
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform

class MainActivity : Activity() {
    private lateinit var status: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!Python.isStarted()) {
            Python.start(AndroidPlatform(this))
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(36, 48, 36, 36)
            setBackgroundColor(Color.rgb(16, 24, 32))
        }

        val title = TextView(this).apply {
            text = "NICE ANTIVIRUS"
            textSize = 26f
            setTextColor(Color.WHITE)
            gravity = Gravity.CENTER
        }
        root.addView(title, matchWrap())

        val subtitle = TextView(this).apply {
            text = "Device security • File analysis • Signature updates"
            textSize = 14f
            setTextColor(Color.LTGRAY)
            gravity = Gravity.CENTER
            setPadding(0, 16, 0, 32)
        }
        root.addView(subtitle, matchWrap())

        status = TextView(this).apply {
            text = "Protection engine ready. Select a folder to scan."
            textSize = 16f
            setTextColor(Color.WHITE)
            setPadding(0, 24, 0, 24)
        }
        root.addView(status, matchWrap())

        val scan = Button(this).apply {
            text = "RUN ENGINE SELF-CHECK"
            setOnClickListener { runSelfCheck() }
        }
        root.addView(scan, matchWrap())

        val update = Button(this).apply {
            text = "CHECK SIGNATURE UPDATE"
            setOnClickListener {
                status.text = "Update service is configured in the Python engine. Set a trusted HTTPS manifest URL before enabling production updates."
            }
        }
        root.addView(update, matchWrap())

        setContentView(root)
    }

    private fun runSelfCheck() {
        try {
            val result = Python.getInstance()
                .getModule("antivirus.scanner")
                .callAttr("engine_self_check")
                .toString()
            status.text = result
        } catch (error: Exception) {
            status.text = "Engine check failed: ${error.localizedMessage ?: "unknown error"}"
        }
    }

    private fun matchWrap() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
    )
}
