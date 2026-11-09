package com.meraj.niceantivirus

import android.app.Activity
import android.app.AlertDialog
import android.app.ActivityManager
import android.app.AppOpsManager
import android.app.usage.UsageStatsManager
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.PackageInfo
import android.os.Build
import android.os.Environment
import android.net.Uri
import android.os.Bundle
import android.os.StatFs
import android.provider.Settings
import android.text.format.Formatter
import android.graphics.Color
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.documentfile.provider.DocumentFile
import androidx.work.ExistingPeriodicWorkPolicy
import androidx.work.PeriodicWorkRequestBuilder
import androidx.work.WorkManager
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import java.io.File
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var scanCount: TextView
    private val worker = Executors.newSingleThreadExecutor()
    private val pickFileRequest = 4101
    private val pickFolderRequest = 4102
    private val restoreRequest = 4103
    private val storageRequest = 4104
    private val exportHistoryRequest = 4105
    private val fileRepairRequest = 4106
    private val saveRepairRequest = 4107
    private var pendingRepairOutput: File? = null
    private var restoreFile: File? = null
    private var refreshPermissionsOnResume = false
    private var pendingFullStorageScan = false
    @Volatile private var scanCancelled = false
    @Volatile private var fullStorageScanActive = false

    private lateinit var pageContainer: LinearLayout
    private lateinit var navigationBar: LinearLayout
    private lateinit var progressCircle: CircularProgressView
    private lateinit var totalFilesLabel: TextView
    private lateinit var processedFilesLabel: TextView
    private lateinit var threatFilesLabel: TextView
    private var currentPage = "home"

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!Python.isStarted()) Python.start(AndroidPlatform(this))

        window.statusBarColor = Color.rgb(6, 13, 24)
        window.navigationBarColor = Color.rgb(6, 13, 24)
        if (Build.VERSION.SDK_INT >= 29) {
            window.isNavigationBarContrastEnforced = false
            window.isStatusBarContrastEnforced = false
        }

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.TOP
            setPadding(dp(15), dp(4), dp(15), dp(4))
            setBackgroundColor(Color.rgb(6, 13, 24))
        }
        // Compact scrollable content column; bottom navigation stays pinned.
        val contentColumn = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.TOP
        }
        val top = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(2), dp(2), dp(2), dp(8))
        }
        top.addView(TextView(this).apply {
            text = "⬡"
            textSize = 29f
            gravity = Gravity.CENTER
            setTextColor(Color.rgb(56, 230, 181))
            background = rounded(Color.rgb(14, 49, 54), dp(13))
        }, LinearLayout.LayoutParams(dp(46), dp(46)))
        val brand = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(10), 0, 0, 0)
        }
        brand.addView(TextView(this).apply {
            text = "NICE ANTIVIRUS"
            textSize = 16f
            letterSpacing = 0.06f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(Color.WHITE)
        }, matchWrap())
        brand.addView(TextView(this).apply {
            text = "SECURITY CENTER"
            textSize = 9f
            letterSpacing = 0.15f
            setTextColor(Color.rgb(120, 150, 174))
        }, matchWrap())
        top.addView(brand, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        top.addView(TextView(this).apply {
            text = "● PROTECTED"
            textSize = 9f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(Color.rgb(60, 224, 171))
            setPadding(dp(10), dp(8), dp(10), dp(8))
            background = rounded(Color.rgb(13, 48, 44), dp(20))
        }, matchWrap())
        contentColumn.addView(top, matchWrap())

        val progressPanel = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(13), dp(10), dp(12), dp(10))
            background = rounded(Color.rgb(16, 29, 45), dp(18))
        }
        progressCircle = CircularProgressView(this)
        progressPanel.addView(progressCircle, LinearLayout.LayoutParams(dp(82), dp(82)))
        val progressInfo = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(13), 0, 0, 0)
        }
        progressInfo.addView(TextView(this).apply {
            text = "SCAN PROGRESS"
            textSize = 10f
            letterSpacing = 0.12f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(Color.rgb(140, 163, 187))
        }, matchWrap())
        totalFilesLabel = TextView(this).apply {
            text = "TOTAL FILES     0"
            textSize = 12f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(Color.WHITE)
            setPadding(0, dp(6), 0, 0)
        }
        progressInfo.addView(totalFilesLabel, matchWrap())
        processedFilesLabel = TextView(this).apply {
            text = "PROCESSED       0"
            textSize = 11f
            setTextColor(Color.rgb(177, 196, 215))
            setPadding(0, dp(3), 0, 0)
        }
        progressInfo.addView(processedFilesLabel, matchWrap())
        threatFilesLabel = TextView(this).apply {
            text = "THREATS             0"
            textSize = 11f
            setTextColor(Color.rgb(255, 180, 110))
            setPadding(0, dp(3), 0, 0)
        }
        progressInfo.addView(threatFilesLabel, matchWrap())
        progressPanel.addView(progressInfo, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        contentColumn.addView(progressPanel, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(104)
        ))

        scanCount = TextView(this).apply {
            text = "READY • 0 files scanned • 0 threat matches"
            textSize = 10f
            setTextColor(Color.rgb(61, 220, 172))
            setPadding(dp(3), dp(5), dp(3), dp(2))
        }
        status = TextView(this).apply {
            text = "Security tools are ready. Select a section from the menu below."
            textSize = 10f
            maxLines = 2
            setLineSpacing(dp(2).toFloat(), 1f)
            setTextColor(Color.rgb(158, 179, 200))
            setOnClickListener {
                val details = TextView(this@MainActivity).apply {
                    text = status.text
                    textSize = 13f
                    setTextColor(Color.rgb(224, 234, 245))
                    setPadding(dp(16), dp(12), dp(16), dp(12))
                }
                AlertDialog.Builder(this@MainActivity)
                    .setTitle("Activity details")
                    .setView(ScrollView(this@MainActivity).apply { addView(details) })
                    .setPositiveButton("Close", null)
                    .show()
            }
        }
        contentColumn.addView(scanCount, matchWrap())
        contentColumn.addView(status, matchWrap())

        pageContainer = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(0, dp(5), 0, dp(5))
        }
        contentColumn.addView(pageContainer, matchWrap())
        // Header, progress, activity and section tools share one compact
        // scroll area, so the tool cards are not pushed below unused space.
        val contentScroll = ScrollView(this).apply {
            isFillViewport = false
            isVerticalScrollBarEnabled = true
            overScrollMode = View.OVER_SCROLL_IF_CONTENT_SCROLLS
            clipToPadding = false
            addView(contentColumn, ViewGroup.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT
            ))
        }
        root.addView(contentScroll, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, 0, 1f
        ))

        navigationBar = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER
            setPadding(dp(3), dp(5), dp(3), dp(3))
            background = rounded(Color.rgb(15, 25, 40), dp(17))
        }
        root.addView(navigationBar, LinearLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT, dp(64)
        ))
        setContentView(root)
        updateScanProgress(0, 0, 0)
        showDashboardPage("home")
    }

    private fun showDashboardPage(page: String) {
        currentPage = page
        pageContainer.removeAllViews()
        val pages = mapOf(
            "home" to Triple("⌂", "DASHBOARD", "Your security overview and quick actions"),
            "protect" to Triple("🛡", "PROTECTION", "Scan and protect your files and apps"),
            "reports" to Triple("▤", "SCAN REPORTS", "Review saved scan activity"),
            "care" to Triple("ϟ", "DEVICE CARE", "Storage, memory and performance tools"),
            "tools" to Triple("⚙", "PRIVACY & ENGINE", "Permissions, monitoring and diagnostics")
        )
        val info = pages[page] ?: pages.getValue("home")
        val pageHeading = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(dp(3), dp(5), dp(3), dp(9))
        }
        pageHeading.addView(TextView(this).apply {
            text = info.first
            textSize = 24f
            gravity = Gravity.CENTER
            setTextColor(Color.rgb(60, 222, 177))
            background = rounded(Color.rgb(18, 48, 55), dp(12))
        }, LinearLayout.LayoutParams(dp(43), dp(43)))
        val headingText = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(10), 0, 0, 0)
        }
        headingText.addView(TextView(this).apply {
            text = info.second
            textSize = 13f
            letterSpacing = 0.09f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(Color.WHITE)
        }, matchWrap())
        headingText.addView(TextView(this).apply {
            text = info.third
            textSize = 10f
            setTextColor(Color.rgb(125, 149, 173))
            setPadding(0, dp(3), 0, 0)
        }, matchWrap())
        pageHeading.addView(headingText, matchWrap())
        pageContainer.addView(pageHeading, matchWrap())

        val protection = listOf(
            "SCAN FILE / APK" to { chooseFile() },
            "SCAN ENTIRE STORAGE" to { requestFullStorageScan() },
            "SCAN FOLDER / SD CARD" to { chooseFolder() },
            "CANCEL CURRENT SCAN" to { cancelCurrentScan() },
            "SCAN INSTALLED APPS" to { scanInstalledApps() },
            "QUARANTINE / RESTORE" to { showQuarantine() }
        )
        val reports = listOf(
            "SCAN HISTORY" to { showScanHistory() },
            "DUPLICATE CONTENT" to { showDuplicateContentReview() },
            "EXPORT REPORT" to { exportScanHistory() },
            "CLEAR HISTORY" to { confirmClearScanHistory() }
        )
        val care = listOf(
            "STORAGE ANALYZER" to { chooseStorageFolder() },
            "RAM & STORAGE" to { showDeviceHealth() },
            "PERFORMANCE ASSIST" to { runPerformanceAssist() },
            "BACKGROUND APP MANAGER" to { showBackgroundAppManager() }
        )
        val tools = listOf(
            "PERMISSION CENTER" to { showPermissionSetup() },
            "APP ACTIVITY" to { showAppActivityMonitor() },
            "PROTECTED APPS" to { showImportantAppsIgnoreList() },
            "START AUTO MONITOR" to { startScheduledMonitoring() },
            "STOP AUTO MONITOR" to { stopScheduledMonitoring() },
            "TOOL CHECKER" to { runToolDiagnostics() },
            "ENGINE SELF-CHECK" to { runSelfCheck() },
            "VIRUS DATABASE UPDATE" to { updateVirusDatabase() },
            "FILE REPAIR" to { chooseFileForRepair() }
        )
        when (page) {
            "home" -> {
                val hero = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    setPadding(dp(16), dp(15), dp(16), dp(15))
                    background = rounded(Color.rgb(13, 43, 54), dp(17))
                }
                hero.addView(TextView(this).apply {
                    text = "YOUR DEVICE. YOUR CONTROL."
                    textSize = 17f
                    setTypeface(null, android.graphics.Typeface.BOLD)
                    setTextColor(Color.WHITE)
                }, matchWrap())
                hero.addView(TextView(this).apply {
                    text = "Fast access to scanning, privacy and device care."
                    textSize = 11f
                    setTextColor(Color.rgb(170, 199, 210))
                    setPadding(0, dp(5), 0, dp(12))
                }, matchWrap())
                val quick = TextView(this).apply {
                    text = "⌕     START QUICK SCAN"
                    gravity = Gravity.CENTER
                    textSize = 13f
                    setTypeface(null, android.graphics.Typeface.BOLD)
                    setTextColor(Color.rgb(4, 30, 31))
                    background = rounded(Color.rgb(57, 225, 177), dp(12))
                    setOnClickListener { chooseFile() }
                    isClickable = true
                    isFocusable = true
                }
                hero.addView(quick, LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT, dp(47)))
                pageContainer.addView(hero, matchWrap())
                val label = TextView(this).apply {
                    text = "QUICK TOOLS"
                    textSize = 10f
                    letterSpacing = 0.12f
                    setTypeface(null, android.graphics.Typeface.BOLD)
                    setTextColor(Color.rgb(137, 160, 184))
                    setPadding(dp(3), dp(14), 0, dp(5))
                }
                pageContainer.addView(label, matchWrap())
                addToolGrid(pageContainer, listOf(
                    "SCAN ENTIRE STORAGE" to { requestFullStorageScan() },
                    "SCAN FOLDER / SD CARD" to { chooseFolder() },
                    "SCAN INSTALLED APPS" to { scanInstalledApps() },
                    "QUARANTINE / RESTORE" to { showQuarantine() }
                ), 72)
            }
            "protect" -> addToolGrid(pageContainer, protection, 76)
            "reports" -> addToolGrid(pageContainer, reports, 76)
            "care" -> {
                addToolGrid(pageContainer, care, 76)
                val note = TextView(this).apply {
                    text = "Storage Analyzer: choose a folder to review files. RAM & Storage: view device status. Performance Assist: clear this app's cache or open Android app controls. Background App Manager: choose an app to review in Android Settings."
                    textSize = 10f
                    setLineSpacing(dp(2).toFloat(), 1f)
                    setTextColor(Color.rgb(135, 158, 181))
                    setPadding(dp(4), dp(9), dp(4), dp(8))
                }
                pageContainer.addView(note, matchWrap())
            }
            else -> addToolGrid(pageContainer, tools, 70)
        }

        navigationBar.removeAllViews()
        val nav = listOf(
            Triple("home", "⌂", "HOME"),
            Triple("protect", "🛡", "PROTECT"),
            Triple("reports", "▤", "REPORTS"),
            Triple("care", "ϟ", "CARE"),
            Triple("tools", "⚙", "TOOLS")
        )
        nav.forEach { item ->
            val selected = item.first == page
            val tab = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                gravity = Gravity.CENTER
                setPadding(dp(2), dp(4), dp(2), dp(3))
                background = if (selected) rounded(Color.rgb(25, 58, 61), dp(12))
                    else rounded(Color.TRANSPARENT, dp(12))
                isClickable = true
                isFocusable = true
                setOnClickListener { showDashboardPage(item.first) }
            }
            tab.addView(TextView(this).apply {
                text = item.second
                textSize = 18f
                gravity = Gravity.CENTER
                setTextColor(if (selected) Color.rgb(66, 230, 181) else Color.rgb(132, 151, 174))
            }, matchWrap())
            tab.addView(TextView(this).apply {
                text = item.third
                textSize = 8f
                letterSpacing = 0.04f
                setTypeface(null, android.graphics.Typeface.BOLD)
                setTextColor(if (selected) Color.WHITE else Color.rgb(132, 151, 174))
            }, matchWrap())
            navigationBar.addView(tab, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.MATCH_PARENT, 1f))
        }
    }

    private fun addToolGrid(
        parent: LinearLayout,
        items: List<Pair<String, () -> Unit>>,
        tileHeight: Int
    ) {
        items.chunked(2).forEachIndexed { rowIndex, pair ->
            val row = LinearLayout(this).apply { orientation = LinearLayout.HORIZONTAL }
            pair.forEachIndexed { index, item ->
                val key = item.first
                val palette = when {
                    key.contains("SCAN") -> intArrayOf(Color.rgb(12, 126, 111), Color.rgb(37, 204, 165), Color.rgb(8, 75, 73))
                    key.contains("QUARANTINE") || key.contains("PROTECTED") -> intArrayOf(Color.rgb(113, 57, 143), Color.rgb(205, 128, 255), Color.rgb(68, 35, 101))
                    key.contains("HISTORY") || key.contains("REPORT") || key.contains("DUPLICATE") -> intArrayOf(Color.rgb(38, 91, 164), Color.rgb(117, 177, 255), Color.rgb(25, 54, 111))
                    key.contains("STORAGE") || key.contains("RAM") -> intArrayOf(Color.rgb(155, 91, 27), Color.rgb(255, 190, 92), Color.rgb(101, 57, 20))
                    key.contains("PERFORMANCE") || key.contains("BACKGROUND") -> intArrayOf(Color.rgb(151, 70, 43), Color.rgb(255, 145, 102), Color.rgb(104, 43, 32))
                    key.contains("PERMISSION") || key.contains("APP") -> intArrayOf(Color.rgb(103, 72, 157), Color.rgb(191, 163, 255), Color.rgb(57, 43, 111))
                    key.contains("MONITOR") -> intArrayOf(Color.rgb(25, 111, 144), Color.rgb(92, 213, 235), Color.rgb(18, 66, 100))
                    key.contains("CHECK") || key.contains("DATABASE") -> intArrayOf(Color.rgb(37, 105, 123), Color.rgb(104, 221, 226), Color.rgb(20, 66, 85))
                    else -> intArrayOf(Color.rgb(60, 86, 112), Color.rgb(157, 190, 220), Color.rgb(34, 53, 76))
                }
                val base = palette[0]
                val accent = palette[1]
                val deep = palette[2]
                val icon = when {
                    key.contains("SCAN") -> "⌕"
                    key.contains("QUARANTINE") -> "▣"
                    key.contains("HISTORY") || key.contains("REPORT") -> "▤"
                    key.contains("DUPLICATE") -> "⧉"
                    key.contains("STORAGE") -> "▦"
                    key.contains("RAM") -> "◉"
                    key.contains("PERFORMANCE") -> "ϟ"
                    key.contains("APP") -> "◈"
                    key.contains("PERMISSION") -> "◇"
                    key.contains("MONITOR") -> "◷"
                    key.contains("CHECK") -> "✓"
                    key.contains("DATABASE") -> "⬡"
                    else -> "›"
                }
                val tile = LinearLayout(this).apply {
                    orientation = LinearLayout.HORIZONTAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(dp(9), dp(7), dp(7), dp(7))
                    background = rounded(base, dp(14))
                    elevation = dp(2).toFloat()
                    isClickable = true
                    isFocusable = true
                    setOnClickListener {
                        try {
                            item.second()
                        } catch (error: Exception) {
                            status.text = key + " failed: " + (error.localizedMessage ?: error.javaClass.simpleName)
                            scanCount.text = "Action could not be started"
                        }
                    }
                }
                tile.addView(TextView(this).apply {
                    text = icon
                    textSize = 23f
                    gravity = Gravity.CENTER
                    setTextColor(Color.WHITE)
                    background = rounded(deep, dp(11))
                }, LinearLayout.LayoutParams(dp(40), dp(40)))
                tile.addView(TextView(this).apply {
                    text = key
                    textSize = 10f
                    maxLines = 2
                    setLineSpacing(dp(2).toFloat(), 1f)
                    setTypeface(null, android.graphics.Typeface.BOLD)
                    setTextColor(Color.WHITE)
                    setPadding(dp(8), 0, 0, 0)
                }, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
                tile.addView(TextView(this).apply {
                    text = "›"
                    textSize = 19f
                    setTypeface(null, android.graphics.Typeface.BOLD)
                    setTextColor(accent)
                }, LinearLayout.LayoutParams(dp(15), ViewGroup.LayoutParams.WRAP_CONTENT))
                row.addView(tile, LinearLayout.LayoutParams(0, dp(tileHeight), 1f).apply {
                    if (index == 0) marginEnd = dp(6) else marginStart = dp(1)
                })
            }
            if (pair.size == 1) row.addView(android.view.View(this),
                LinearLayout.LayoutParams(0, dp(tileHeight), 1f))
            val params = matchWrap()
            params.topMargin = dp(8)
            parent.addView(row, params)
        }
    }

    private fun updateScanProgress(total: Int, done: Int, threats: Int) {
        val safeTotal = total.coerceAtLeast(0)
        val safeDone = done.coerceIn(0, safeTotal.coerceAtLeast(0))
        val percent = if (safeTotal == 0) 0 else ((safeDone * 100L) / safeTotal).toInt()
        progressCircle.setProgress(percent)
        totalFilesLabel.text = "TOTAL FILES     " + safeTotal
        processedFilesLabel.text = "PROCESSED       " + safeDone + " / " + safeTotal
        threatFilesLabel.text = "THREATS             " + threats
    }

    private class CircularProgressView(context: android.content.Context) : android.view.View(context) {
        private val track = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
            style = android.graphics.Paint.Style.STROKE
            strokeWidth = 8f * resources.displayMetrics.density
            strokeCap = android.graphics.Paint.Cap.ROUND
            color = Color.rgb(42, 59, 75)
        }
        private val arc = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
            style = android.graphics.Paint.Style.STROKE
            strokeWidth = 8f * resources.displayMetrics.density
            strokeCap = android.graphics.Paint.Cap.ROUND
            color = Color.rgb(55, 226, 177)
        }
        private val label = android.graphics.Paint(android.graphics.Paint.ANTI_ALIAS_FLAG).apply {
            color = Color.WHITE
            textAlign = android.graphics.Paint.Align.CENTER
            typeface = android.graphics.Typeface.create("sans-serif", android.graphics.Typeface.BOLD)
            textSize = 25f * resources.displayMetrics.density
        }
        private var percent = 0
        fun setProgress(value: Int) {
            percent = value.coerceIn(0, 100)
            invalidate()
        }
        override fun onDraw(canvas: android.graphics.Canvas) {
            super.onDraw(canvas)
            val stroke = track.strokeWidth
            val radius = (minOf(width, height) / 2f) - stroke
            val cx = width / 2f
            val cy = height / 2f
            val bounds = android.graphics.RectF(cx - radius, cy - radius, cx + radius, cy + radius)
            canvas.drawArc(bounds, 0f, 360f, false, track)
            if (percent > 0) canvas.drawArc(bounds, -90f, 360f * percent / 100f, false, arc)
            val baseline = cy - (label.ascent() + label.descent()) / 2f
            canvas.drawText("$percent%", cx, baseline, label)
        }
    }

    override fun onResume() {
        super.onResume()
        if (pendingFullStorageScan && Build.VERSION.SDK_INT >= 30 && Environment.isExternalStorageManager()) {
            pendingFullStorageScan = false
            startFullStorageScan()
        }
        if (refreshPermissionsOnResume) {
            refreshPermissionsOnResume = false
            showPermissionSetup()
        }
    }

    @Deprecated("Uses the platform permission callback for broad Android compatibility")
    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == 4201) showPermissionSetup()
        if (requestCode == 4301 && grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) startFullStorageScan()
    }

    private fun addSection(
        parent: LinearLayout,
        heading: String,
        subtitle: String,
        items: List<Pair<String, () -> Unit>>
    ) {
        val accent = when (heading) {
            "PROTECTION" -> Color.rgb(52, 219, 174)
            "SCAN REPORTS" -> Color.rgb(105, 174, 255)
            "DEVICE CARE" -> Color.rgb(255, 190, 94)
            "APP PRIVACY" -> Color.rgb(185, 151, 255)
            else -> Color.rgb(81, 207, 224)
        }
        val symbol = when (heading) {
            "PROTECTION" -> "🛡"
            "SCAN REPORTS" -> "▤"
            "DEVICE CARE" -> "⌁"
            "APP PRIVACY" -> "◈"
            else -> "⚙"
        }
        val card = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(15), dp(15), dp(15), dp(14))
            background = rounded(Color.rgb(15, 25, 40), dp(18))
        }
        val headingRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
        }
        headingRow.addView(TextView(this).apply {
            text = symbol
            textSize = 22f
            gravity = Gravity.CENTER
            setTextColor(accent)
            background = rounded(Color.rgb(25, 40, 57), dp(11))
        }, LinearLayout.LayoutParams(dp(42), dp(42)))
        val headingText = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(11), 0, 0, 0)
        }
        headingText.addView(TextView(this).apply {
            text = heading
            textSize = 13f
            letterSpacing = 0.08f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(Color.WHITE)
        }, matchWrap())
        headingText.addView(TextView(this).apply {
            text = subtitle
            textSize = 10f
            setTextColor(Color.rgb(126, 148, 173))
            setPadding(0, dp(3), 0, 0)
        }, matchWrap())
        headingRow.addView(headingText, LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f))
        headingRow.addView(TextView(this).apply {
            text = items.size.toString().padStart(2, '0')
            textSize = 10f
            setTypeface(null, android.graphics.Typeface.BOLD)
            setTextColor(accent)
        }, matchWrap())
        card.addView(headingRow, matchWrap())

        items.chunked(2).forEach { pair ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
            }
            pair.forEachIndexed { index, item ->
                val tile = LinearLayout(this).apply {
                    orientation = LinearLayout.VERTICAL
                    gravity = Gravity.CENTER_VERTICAL
                    setPadding(dp(11), dp(8), dp(8), dp(8))
                    background = rounded(Color.rgb(25, 39, 57), dp(12))
                    isClickable = true
                    isFocusable = true
                    setOnClickListener { item.second() }
                }
                val glyph = when {
                    item.first.contains("SCAN") -> "⌕"
                    item.first.contains("QUARANTINE") -> "▣"
                    item.first.contains("HISTORY") || item.first.contains("REPORT") -> "▤"
                    item.first.contains("DUPLICATE") -> "⧉"
                    item.first.contains("STORAGE") -> "▦"
                    item.first.contains("RAM") -> "◉"
                    item.first.contains("PERFORMANCE") -> "ϟ"
                    item.first.contains("APP") -> "▣"
                    item.first.contains("PERMISSION") -> "◇"
                    item.first.contains("MONITOR") -> "◷"
                    item.first.contains("CHECK") -> "✓"
                    item.first.contains("DATABASE") -> "⬡"
                    else -> "›"
                }
                tile.addView(TextView(this).apply {
                    text = glyph
                    textSize = 19f
                    setTextColor(accent)
                }, matchWrap())
                tile.addView(TextView(this).apply {
                    text = item.first
                    textSize = 10f
                    maxLines = 2
                    setLineSpacing(dp(2).toFloat(), 1f)
                    setTypeface(null, android.graphics.Typeface.BOLD)
                    setTextColor(Color.rgb(218, 229, 240))
                    setPadding(0, dp(4), 0, 0)
                }, matchWrap())
                row.addView(tile, LinearLayout.LayoutParams(0, dp(76), 1f).apply {
                    if (index == 0) marginEnd = dp(7) else marginStart = dp(1)
                })
            }
            if (pair.size == 1) row.addView(android.view.View(this),
                LinearLayout.LayoutParams(0, dp(76), 1f))
            val rowParams = matchWrap()
            rowParams.topMargin = dp(9)
            card.addView(row, rowParams)
        }
        val params = matchWrap()
        params.topMargin = dp(13)
        parent.addView(card, params)
    }

    private fun rounded(color: Int, radius: Int): android.graphics.drawable.GradientDrawable {
        return android.graphics.drawable.GradientDrawable().apply {
            setColor(color)
            cornerRadius = radius.toFloat()
        }
    }

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    private fun addButton(parent: LinearLayout, label: String, action: () -> Unit) {
        val button = Button(this).apply {
            text = label
            isAllCaps = false
            setTextColor(Color.WHITE)
            background = rounded(Color.rgb(31, 47, 67), dp(10))
            setOnClickListener { action() }
        }
        parent.addView(button, matchWrap().apply { topMargin = dp(10) })
    }

    private fun chooseFile() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        startActivityForResult(intent, pickFileRequest)
    }

    private fun chooseFolder() {
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), pickFolderRequest)
    }

    private fun requestFullStorageScan() {
        if (Build.VERSION.SDK_INT >= 30) {
            if (Environment.isExternalStorageManager()) { startFullStorageScan(); return }
            pendingFullStorageScan = true
            try {
                startActivity(Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION, Uri.parse("package:" + packageName)))
            } catch (e: Exception) {
                pendingFullStorageScan = false
                status.text = "Full storage permission unavailable. Use SCAN FOLDER / SD CARD."
            }
        } else if (checkSelfPermission(android.Manifest.permission.READ_EXTERNAL_STORAGE) == PackageManager.PERMISSION_GRANTED) {
            startFullStorageScan()
        } else {
            requestPermissions(arrayOf(android.Manifest.permission.READ_EXTERNAL_STORAGE), 4301)
        }
    }

    private fun startFullStorageScan() {
        synchronized(this) {
            if (fullStorageScanActive) {
                runOnUiThread { status.text = "Full storage scan is already running. Please wait for it to finish." }
                return
            }
            fullStorageScanActive = true
        }
        scanCancelled = false
        runOnUiThread {
            status.text = "Indexing all accessible shared-storage files…"
            scanCount.text = "Finding files… no 5,000-file limit"
            updateScanProgress(0, 0, 0)
        }
        worker.execute {
            try {
                val root = Environment.getExternalStorageDirectory().canonicalFile
                val rootPath = root.toPath()
                val queue = java.util.ArrayDeque<File>()
                val visitedDirectories = HashSet<String>()
                val uris = ArrayList<Uri>()
                queue.add(root)
                var visitedEntries = 0
                var inaccessible = 0
                while (queue.isNotEmpty() && !scanCancelled) {
                    val dir = queue.removeFirst()
                    val canonicalDir = try { dir.canonicalFile } catch (_: Exception) { inaccessible++; continue }
                    if (!visitedDirectories.add(canonicalDir.absolutePath)) continue
                    val children = try { canonicalDir.listFiles() } catch (_: Exception) { null }
                    if (children == null) { inaccessible++; continue }
                    for (child in children) {
                        if (scanCancelled) break
                        visitedEntries++
                        try {
                            val file = child.canonicalFile
                            if (!file.toPath().startsWith(rootPath)) continue
                            if (file.isDirectory) {
                                val childPath = file.absolutePath
                                if (!childPath.contains("/Android/data/") && !childPath.contains("/Android/obb/")) {
                                    if (!visitedDirectories.contains(childPath)) queue.add(file)
                                } else inaccessible++
                            } else if (file.isFile && file.canRead()) uris.add(Uri.fromFile(file))
                            else inaccessible++
                        } catch (_: Exception) { inaccessible++ }
                    }
                    if (visitedEntries % 500 == 0) {
                        val found = uris.size
                        val checked = visitedEntries
                        runOnUiThread { status.text = "Indexing storage… $found files found, $checked entries checked." }
                    }
                }
                if (scanCancelled) {
                    fullStorageScanActive = false
                    runOnUiThread {
                        status.text = "Storage indexing cancelled. ${uris.size} files were found but not scanned."
                        scanCount.text = "CANCELLED • ${uris.size} files found"
                    }
                    return@execute
                }
                if (uris.isEmpty()) {
                    fullStorageScanActive = false
                    runOnUiThread {
                        updateScanProgress(0, 0, 0)
                        status.text = "No readable files found. Check All files access permission."
                        scanCount.text = "0 files found"
                    }
                } else {
                    val total = uris.size
                    runOnUiThread {
                        status.text = "Index complete. Scanning all $total accessible files now."
                        scanCount.text = "0 / $total files • $inaccessible inaccessible entries skipped"
                        scanUris(uris)
                    }
                }
            } catch (e: Exception) {
                fullStorageScanActive = false
                runOnUiThread {
                    status.text = "Full storage scan failed: " + (e.localizedMessage ?: e.javaClass.simpleName)
                    scanCount.text = "Scan unavailable"
                }
            }
        }
    }
    @Deprecated("Uses the platform document picker for broad Android compatibility")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data?.data == null) return
        val uri = data.data!!
        if (requestCode == pickFolderRequest) {
            val flags = data.flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            try { contentResolver.takePersistableUriPermission(uri, flags) } catch (_: SecurityException) {}
            scanFolder(uri)
        } else if (requestCode == pickFileRequest) {
            scanUris(listOf(uri))
        } else if (requestCode == storageRequest) {
            val flags = data.flags and (Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_GRANT_WRITE_URI_PERMISSION)
            try { contentResolver.takePersistableUriPermission(uri, flags) } catch (_: SecurityException) {}
            analyzeStorageTree(uri)
        } else if (requestCode == fileRepairRequest) {
            repairSelectedDocument(uri)
        } else if (requestCode == saveRepairRequest) {
            val repaired = pendingRepairOutput
            pendingRepairOutput = null
            if (repaired != null && repaired.isFile) {
                worker.execute {
                    try {
                        contentResolver.openOutputStream(uri, "w")?.use { output ->
                            repaired.inputStream().use { input -> input.copyTo(output) }
                        } ?: throw IllegalStateException("Cannot create destination file")
                        runOnUiThread {
                            status.text = "REPAIR COPY SAVED: " + (queryDisplayName(uri) ?: repaired.name)
                            scanCount.text = "Repaired copy exported • original unchanged"
                        }
                    } catch (error: Exception) {
                        runOnUiThread { status.text = "Could not save repaired copy: " + (error.localizedMessage ?: "unknown error") }
                    }
                }
            }
        } else if (requestCode == exportHistoryRequest) {
            worker.execute {
                try {
                    val report = Python.getInstance().getModule("antivirus.scanner")
                        .callAttr("scan_history_report", File(filesDir, "signatures.db").absolutePath, 200)
                        .toString()
                    contentResolver.openOutputStream(uri, "w")?.use { output ->
                        output.write(("NICE ANTIVIRUS - SCAN HISTORY\n\n" + report +
                            "\n\nExported locally. No-match does not guarantee a file is safe.").toByteArray(Charsets.UTF_8))
                    } ?: throw IllegalStateException("Cannot create report file")
                    runOnUiThread { status.text = "Scan report exported successfully." }
                } catch (error: Exception) {
                    runOnUiThread { status.text = "Report export failed: " + (error.localizedMessage ?: "unknown error") }
                }
            }
        } else if (requestCode == restoreRequest) {
            val source = restoreFile
            restoreFile = null
            if (source != null && source.exists()) {
                worker.execute {
                    try {
                        contentResolver.openOutputStream(uri, "w")?.use { output ->
                            source.inputStream().use { input -> input.copyTo(output) }
                        } ?: throw IllegalStateException("Cannot create destination file")
                        runOnUiThread { status.text = "Restored a copy of " + source.name + ". Quarantine copy was kept." }
                    } catch (error: Exception) {
                        runOnUiThread { status.text = "Restore failed: " + (error.localizedMessage ?: "unknown error") }
                    }
                }
            }
        }
    }

    private fun scanFolder(treeUri: Uri) {
        runOnUiThread { status.text = "Reading selected folder…" }
        worker.execute {
            val files = mutableListOf<Uri>()
            val root = DocumentFile.fromTreeUri(this, treeUri)
            fun walk(directory: DocumentFile, depth: Int) {
                if (depth > 20 || files.size >= 5000) return
                directory.listFiles().forEach { child ->
                    if (child.isDirectory) walk(child, depth + 1)
                    else if (child.isFile) files.add(child.uri)
                }
            }
            if (root != null) walk(root, 0)
            scanUris(files)
        }
    }

    private fun cancelCurrentScan() {
        scanCancelled = true
        status.text = "Scan cancellation requested. The current file will finish before the next file is skipped."
    }

    private fun scanUris(uris: List<Uri>) {
        scanCancelled = false
        val total = uris.size
        runOnUiThread {
            updateScanProgress(total, 0, 0)
            status.text = "Preparing scan of $total file(s)…"
        }
        if (uris.isEmpty()) {
            fullStorageScanActive = false
            runOnUiThread {
                updateScanProgress(0, 0, 0)
                status.text = "No files were found in the selected location."
            }
            return
        }
        worker.execute {
            val results = mutableListOf<String>()
            val detectedTemps = mutableListOf<Pair<String, File>>()
            var threats = 0
            var done = 0
            val python = Python.getInstance().getModule("antivirus.scanner")
            val cache = File(cacheDir, "scan")
            cache.mkdirs()
            for ((index, uri) in uris.withIndex()) {
                if (scanCancelled) break
                try {
                    val name = queryDisplayName(uri) ?: "selected_file"
                    val safeName = name.replace(Regex("[^A-Za-z0-9._-]"), "_").take(100)
                    val temp = File.createTempFile("scan_", "_" + safeName, cache)
                    contentResolver.openInputStream(uri)?.use { input ->
                        temp.outputStream().use { output -> input.copyTo(output) }
                    } ?: throw IllegalStateException("Cannot open selected document")
                    val result = python.callAttr("scan_local_file", temp.absolutePath, File(filesDir, "signatures.db").absolutePath, name).toString()
                    val apkReview = if (name.endsWith(".apk", ignoreCase = true)) inspectApkPermissions(temp) else ""
                    if (result.startsWith("THREAT MATCH:")) {
                        threats++
                        detectedTemps.add(Pair(name, temp))
                    } else {
                        temp.delete()
                    }
                    results.add(name + ": " + result + apkReview)
                } catch (error: Exception) {
                    results.add(uri.toString() + ": ERROR - " + (error.localizedMessage ?: "unreadable"))
                }
                done = index + 1
                val currentDone = done
                val currentThreats = threats
                val currentLocation = if (uri.scheme == "file") uri.path ?: uri.toString() else queryDisplayName(uri) ?: uri.toString()
                runOnUiThread {
                    updateScanProgress(total, currentDone, currentThreats)
                    // The progress panel already shows totals; keep this line for the
                    // actual file being scanned rather than repeating the counters.
                    status.text = "SCANNING: " + currentLocation
                }
            }
            val wasCancelled = scanCancelled
            scanCancelled = false
            val summary = results.take(40).joinToString("\n\n")
            fullStorageScanActive = false
            runOnUiThread {
                status.text = (if (wasCancelled) "SCAN CANCELLED" else "SCAN FINISHED") + "\n\n" + summary +
                    if (results.size > 40) "\n\n…and " + (results.size - 40) + " more items." else ""
                if (wasCancelled) status.append("\n\nRemaining files were not scanned.")
                updateScanProgress(total, done, threats)
                if (detectedTemps.isNotEmpty()) {
                    AlertDialog.Builder(this)
                        .setTitle("Threat matches found")
                        .setMessage(threats.toString() + " file(s) matched local signatures. Copy matched files to the app-private quarantine? Original files will NOT be deleted or changed.")
                        .setNegativeButton("Not now") { _, _ -> detectedTemps.forEach { it.second.delete() } }
                        .setPositiveButton("Copy to quarantine") { _, _ ->
                            worker.execute {
                                val saved = mutableListOf<String>()
                                val folder = File(filesDir, "quarantine").apply { mkdirs() }
                                detectedTemps.forEach { item ->
                                    try {
                                        val target = File(folder, System.currentTimeMillis().toString() + "_" + item.second.name)
                                        item.second.copyTo(target, overwrite = false)
                                        File(target.absolutePath + ".meta").writeText(item.first)
                                        saved.add(item.first)
                                    } catch (_: Exception) { }
                                    item.second.delete()
                                }
                                runOnUiThread {
                                    status.text = "Quarantine saved " + saved.size + " file(s) in app-private storage. Original files remain unchanged; manually remove originals only after verifying the detection."
                                }
                            }
                        }
                        .show()
                }
            }
        }
    }

    @Suppress("DEPRECATION")
    private fun hasUsageAccess(): Boolean {
        return try {
            val appOps = getSystemService(APP_OPS_SERVICE) as AppOpsManager
            val mode = if (Build.VERSION.SDK_INT >= 29) {
                appOps.unsafeCheckOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), packageName)
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(AppOpsManager.OPSTR_GET_USAGE_STATS, android.os.Process.myUid(), packageName)
            }
            mode == AppOpsManager.MODE_ALLOWED
        } catch (_: Exception) {
            false
        }
    }

    private fun showAppActivityMonitor() {
        if (!hasUsageAccess()) {
            AlertDialog.Builder(this)
                .setTitle("Usage Access required")
                .setMessage("Allow Usage Access for Nice Antivirus in Android Settings. This lets the app review recent app-usage records; it does not reveal downloads or prove an app is safe or harmful.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Open Settings") { _, _ ->
                    try {
                        startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
                    } catch (_: Exception) {
                        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
                    }
                }
                .show()
            return
        }

        status.text = "Reading recent app-usage records…"
        scanCount.text = "App activity review running…"
        worker.execute {
            try {
                val usageManager = getSystemService(USAGE_STATS_SERVICE) as UsageStatsManager
                val end = System.currentTimeMillis()
                val start = end - 24L * 60L * 60L * 1000L
                val records = usageManager.queryUsageStats(UsageStatsManager.INTERVAL_DAILY, start, end)
                    .orEmpty()
                    .filter { it.packageName != packageName && it.totalTimeInForeground > 0L }
                    .groupBy { it.packageName }
                    .map { entry ->
                        val latest = entry.value.maxOfOrNull { it.lastTimeUsed } ?: 0L
                        val foreground = entry.value.sumOf { it.totalTimeInForeground }
                        Triple(entry.key, latest, foreground)
                    }
                    .sortedByDescending { it.second }
                    .take(40)

                val protectedPackages = getSharedPreferences("nice_antivirus_settings", MODE_PRIVATE)
                    .getStringSet("important_apps_ignore", emptySet()).orEmpty()
                val report = if (records.isEmpty()) {
                    "No app-usage records were returned for the last 24 hours. Check Usage Access and use the phone normally, then try again."
                } else {
                    records.joinToString("\n\n") { item ->
                        val label = try {
                            val app = if (Build.VERSION.SDK_INT >= 33) {
                                packageManager.getApplicationInfo(item.first, PackageManager.ApplicationInfoFlags.of(0))
                            } else {
                                @Suppress("DEPRECATION")
                                packageManager.getApplicationInfo(item.first, 0)
                            }
                            packageManager.getApplicationLabel(app).toString()
                        } catch (_: Exception) { item.first }
                        val minutes = item.third / 60000L
                        val last = if (item.second > 0L) java.text.DateFormat.getDateTimeInstance().format(java.util.Date(item.second)) else "Unknown"
                        (if (item.first in protectedPackages) "★ PROTECTED APP\n" else "") + "$label\nPackage: ${item.first}\nForeground use: ${minutes} min\nLast used: $last"
                    }
                }
                runOnUiThread {
                    scanCount.text = records.size.toString() + " apps with usage records • last 24 hours"
                    status.text = "APP ACTIVITY MONITOR • LAST 24 HOURS\n\n" + report +
                        "\n\nImportant: usage history is not a live running-process list. It cannot identify downloads, uploads or background work, and it must never be used alone to force-stop an app."
                }
            } catch (error: Exception) {
                runOnUiThread {
                    status.text = "App activity review failed: " + (error.localizedMessage ?: "unknown error") +
                        "\nCheck Usage Access in Permission Setup."
                    scanCount.text = "Activity review unavailable"
                }
            }
        }
    }


    private fun showImportantAppsIgnoreList() {
        status.text = "Loading installed apps…"
        worker.execute {
            try {
                val launchIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                val apps = packageManager.queryIntentActivities(launchIntent, 0)
                    .mapNotNull { info ->
                        val pkg = info.activityInfo?.packageName ?: return@mapNotNull null
                        if (pkg == packageName) return@mapNotNull null
                        val label = info.loadLabel(packageManager)?.toString() ?: pkg
                        pkg to label
                    }
                    .distinctBy { it.first }
                    .sortedBy { it.second.lowercase(java.util.Locale.ROOT) }
                val prefs = getSharedPreferences("nice_antivirus_settings", MODE_PRIVATE)
                val saved = prefs.getStringSet("important_apps_ignore", emptySet()).orEmpty()
                val selected = apps.map { it.first in saved }.toBooleanArray()
                val labels = apps.map { it.second + "\n" + it.first }.toTypedArray()
                runOnUiThread {
                    if (apps.isEmpty()) {
                        status.text = "No launcher apps were found to add to the ignore list."
                        return@runOnUiThread
                    }
                    AlertDialog.Builder(this)
                        .setTitle("Important Apps • Ignore List")
                        .setMultiChoiceItems(labels, selected) { _, which, checked ->
                            selected[which] = checked
                        }
                        .setPositiveButton("Save") { _, _ ->
                            val protected = apps.indices.filter { selected[it] }.map { apps[it].first }.toSet()
                            prefs.edit().putStringSet("important_apps_ignore", protected).apply()
                            status.text = "IMPORTANT APPS IGNORE LIST\n\nSaved ${protected.size} protected app(s). These apps will be marked as protected in the activity report and excluded from future Nice Antivirus app-management recommendations. Android itself may still manage apps normally."
                            scanCount.text = "${protected.size} important app(s) protected"
                        }
                        .setNeutralButton("Clear all") { _, _ ->
                            prefs.edit().remove("important_apps_ignore").apply()
                            status.text = "Important Apps Ignore List cleared."
                            scanCount.text = "No apps marked as protected"
                        }
                        .setNegativeButton("Cancel", null)
                        .show()
                }
            } catch (error: Exception) {
                runOnUiThread {
                    status.text = "Could not load the app list: " + (error.localizedMessage ?: "unknown error")
                }
            }
        }
    }


    private fun startScheduledMonitoring() {
        if (!hasUsageAccess()) {
            AlertDialog.Builder(this)
                .setTitle("Usage Access required")
                .setMessage("Enable Usage Access before scheduling monitoring. Android will run checks periodically (at least 15 minutes apart); battery optimization may delay them.")
                .setNegativeButton("Cancel", null)
                .setPositiveButton("Open Settings") { _, _ ->
                    try {
                        startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
                    } catch (_: Exception) {
                        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
                    }
                }
                .show()
            return
        }

        val request = PeriodicWorkRequestBuilder<AppActivityMonitorWorker>(
            15, TimeUnit.MINUTES
        ).build()
        WorkManager.getInstance(applicationContext).enqueueUniquePeriodicWork(
            AppActivityMonitorWorker.UNIQUE_WORK_NAME,
            ExistingPeriodicWorkPolicy.KEEP,
            request
        )
        getSharedPreferences("nice_antivirus_settings", MODE_PRIVATE).edit()
            .putBoolean("scheduled_activity_monitor_enabled", true).apply()
        val notificationsAllowed = Build.VERSION.SDK_INT < 33 ||
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        status.text = "AUTOMATIC APP ACTIVITY MONITOR SCHEDULED\n\nWorkManager checks usage changes periodically, with a 15-minute minimum interval. Android may defer work because of Doze mode, battery restrictions or device policy. " +
            (if (notificationsAllowed) "Activity summaries can appear as notifications." else "Notifications are currently not permitted; enable them in Permission Setup to receive alerts.") +
            "\n\nThis reports foreground app usage changes only. It does not detect malware, downloads, uploads or background processes, and it never closes apps."
        scanCount.text = "Scheduled monitoring enabled"
    }

    private fun stopScheduledMonitoring() {
        WorkManager.getInstance(applicationContext)
            .cancelUniqueWork(AppActivityMonitorWorker.UNIQUE_WORK_NAME)
        getSharedPreferences("nice_antivirus_settings", MODE_PRIVATE).edit()
            .putBoolean("scheduled_activity_monitor_enabled", false).apply()
        status.text = "Automatic app activity monitoring has been cancelled. No app was stopped or changed."
        scanCount.text = "Scheduled monitoring disabled"
    }

    private fun showPermissionSetup() {
        val usageGranted = hasUsageAccess()
        val notificationGranted = Build.VERSION.SDK_INT < 33 ||
            checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED
        val notificationsEnabled = notificationGranted && androidx.core.app.NotificationManagerCompat.from(this).areNotificationsEnabled()
        val batteryOptimized = if (Build.VERSION.SDK_INT >= 23) {
            !(getSystemService(POWER_SERVICE) as android.os.PowerManager).isIgnoringBatteryOptimizations(packageName)
        } else false
        val monitorEnabled = getSharedPreferences("nice_antivirus_settings", MODE_PRIVATE)
            .getBoolean("scheduled_activity_monitor_enabled", false)
        val report = "NICE ANTIVIRUS • PERMISSION CENTER\n\n" +
            "Usage Access: " + (if (usageGranted) "GRANTED" else "NOT GRANTED") + "\n" +
            "Notifications: " + (if (notificationsEnabled) "ENABLED" else if (!notificationGranted) "PERMISSION NOT GRANTED" else "BLOCKED IN APP SETTINGS") + "\n" +
            "Battery optimization: " + (if (Build.VERSION.SDK_INT < 23) "NOT APPLICABLE" else if (batteryOptimized) "ACTIVE (background work may be delayed)" else "IGNORED FOR THIS APP") + "\n" +
            "Scheduled monitor: " + (if (monitorEnabled) "ENABLED" else "DISABLED") + "\n\n" +
            "Usage Access supports recent foreground-usage reports. It cannot identify downloads/uploads, prove malware or force-stop apps.\n\n" +
            "Notifications are optional alerts. Battery optimization can delay scheduled checks; exempting this app is optional and may increase battery use.\n\n" +
            "Only enable permissions you understand. Nice Antivirus does not need SMS, contacts, camera, accessibility or device-admin access."
        AlertDialog.Builder(this)
            .setTitle("Permission Setup")
            .setMessage(report)
            .setPositiveButton(if (usageGranted) "Review Usage Access" else "Grant Usage Access") { _, _ ->
                refreshPermissionsOnResume = true
                try {
                    startActivity(Intent(Settings.ACTION_USAGE_ACCESS_SETTINGS))
                } catch (_: Exception) {
                    startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
                }
            }
            .setNeutralButton(if (notificationsEnabled) "Notification Settings" else "Enable Notifications") { _, _ ->
                if (Build.VERSION.SDK_INT >= 33 && !notificationGranted) {
                    requestPermissions(arrayOf(android.Manifest.permission.POST_NOTIFICATIONS), 4201)
                } else {
                    refreshPermissionsOnResume = true
                    try {
                        val intent = Intent(Settings.ACTION_APP_NOTIFICATION_SETTINGS)
                            .putExtra(Settings.EXTRA_APP_PACKAGE, packageName)
                        startActivity(intent)
                    } catch (_: Exception) {
                        startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
                    }
                }
            }
            .setNegativeButton("Battery Settings") { _, _ ->
                refreshPermissionsOnResume = true
                try {
                    startActivity(Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS))
                } catch (_: Exception) {
                    startActivity(Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:$packageName")))
                }
            }
            .show()
    }

    private fun showBackgroundAppManager() {
        status.text = "Loading apps available for manual background management…"
        worker.execute {
            val apps = mutableListOf<Pair<String, String>>()
            try {
                val intent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                packageManager.queryIntentActivities(intent, 0).forEach { info ->
                    val packageName = info.activityInfo?.packageName ?: return@forEach
                    if (packageName == packageNameOfThisApp()) return@forEach
                    val label = info.loadLabel(packageManager)?.toString() ?: packageName
                    apps.add(Pair(label, packageName))
                }
            } catch (error: Exception) {
                runOnUiThread { status.text = "Cannot list apps: " + (error.localizedMessage ?: "unknown error") }
                return@execute
            }
            val sorted = apps.distinctBy { it.second }.sortedBy { it.first.lowercase() }
            runOnUiThread {
                scanCount.text = sorted.size.toString() + " apps available for review"
                status.text = "BACKGROUND APP MANAGER\n\nChoose an app to open its Android App Info page. Android will let you decide whether to force stop it."
                if (sorted.isEmpty()) {
                    status.append("\nNo launcher apps were found.")
                } else {
                    AlertDialog.Builder(this)
                        .setTitle("Select app • manual control")
                        .setItems(sorted.map { it.first }.toTypedArray()) { _, index ->
                            val selected = sorted[index]
                            AlertDialog.Builder(this)
                                .setTitle("Review " + selected.first + "?")
                                .setMessage("Only force stop this app if you are sure it is not downloading, uploading, navigating, playing audio, syncing, or processing important work. Nice Antivirus cannot reliably detect those activities. Force stop may cancel downloads and notifications.")
                                .setNegativeButton("Cancel", null)
                                .setPositiveButton("Open App Info") { _, _ ->
                                    try {
                                        val details = Intent(android.provider.Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + selected.second))
                                        startActivity(details)
                                    } catch (error: Exception) {
                                        status.text = "Could not open Android App Info: " + (error.localizedMessage ?: "unknown error")
                                    }
                                }
                                .show()
                        }
                        .setNegativeButton("Close", null)
                        .show()
                }
            }
        }
    }

    private fun packageNameOfThisApp(): String = packageName
    private fun runPerformanceAssist() {
        status.text = "Checking memory, storage and thermal status…"
        scanCount.text = "Performance assist running…"
        worker.execute {
            try {
                val manager = getSystemService(ACTIVITY_SERVICE) as ActivityManager
                val memory = ActivityManager.MemoryInfo()
                manager.getMemoryInfo(memory)
                val stat = StatFs(Environment.getDataDirectory().absolutePath)
                val freeBytes = stat.availableBytes
                val totalBytes = stat.totalBytes
                val freePercent = if (totalBytes > 0L) freeBytes * 100.0 / totalBytes else 0.0
                val cacheBytes = directorySize(cacheDir) + (externalCacheDir?.let { directorySize(it) } ?: 0L)
                val thermal = if (Build.VERSION.SDK_INT >= 29) {
                    val power = getSystemService(POWER_SERVICE) as android.os.PowerManager
                    when (power.currentThermalStatus) {
                        android.os.PowerManager.THERMAL_STATUS_NONE -> "Normal"
                        android.os.PowerManager.THERMAL_STATUS_LIGHT -> "Light"
                        android.os.PowerManager.THERMAL_STATUS_MODERATE -> "Moderate"
                        android.os.PowerManager.THERMAL_STATUS_SEVERE -> "Severe"
                        android.os.PowerManager.THERMAL_STATUS_CRITICAL -> "Critical"
                        android.os.PowerManager.THERMAL_STATUS_EMERGENCY -> "Emergency"
                        android.os.PowerManager.THERMAL_STATUS_SHUTDOWN -> "Shutdown risk"
                        else -> "Unknown"
                    }
                } else "Not available"
                val report = "NICE ANTIVIRUS • BOOST & DEVICE STATUS\n\n" +
                    "AVAILABLE RAM: " + Formatter.formatFileSize(this, memory.availMem) + " / " + Formatter.formatFileSize(this, memory.totalMem) + "\n" +
                    "RAM LOW: " + if (memory.lowMemory) "YES" else "NO" + "\n" +
                    "INTERNAL STORAGE FREE: " + Formatter.formatFileSize(this, freeBytes) + " (" + String.format(java.util.Locale.US, "%.1f", freePercent) + "%)\n" +
                    "NICE ANTIVIRUS CACHE: " + Formatter.formatFileSize(this, cacheBytes) + "\n" +
                    "DEVICE TEMPERATURE STATUS: " + thermal + "\n\n" +
                    "WHAT BOOST CAN DO\n" +
                    "• Clear Nice Antivirus temporary cache.\n" +
                    "• Release unused memory held by this app.\n" +
                    "• Open Android storage/app controls for system-managed cleanup.\n\n" +
                    "Android does not let ordinary apps force-stop every other app or clear their private caches. Android manages RAM automatically; force-stopping apps blindly can interrupt downloads, calls, navigation and sync."
                runOnUiThread {
                    status.text = report
                    scanCount.text = "Device status refreshed • RAM " + Formatter.formatFileSize(this, memory.availMem) + " free"
                    val dialog = AlertDialog.Builder(this)
                        .setTitle("Nice Boost • Safe actions")
                        .setMessage("App cache: " + Formatter.formatFileSize(this, cacheBytes) +
                            "\nFree RAM: " + Formatter.formatFileSize(this, memory.availMem) +
                            "\nFree storage: " + Formatter.formatFileSize(this, freeBytes) +
                            "\n\nChoose a safe action. Other apps will not be killed automatically.")
                        .setNegativeButton("Close", null)
                        .setNeutralButton("Manage Apps") { _, _ ->
                            try {
                                startActivity(Intent(Settings.ACTION_INTERNAL_STORAGE_SETTINGS))
                            } catch (_: Exception) {
                                startActivity(Intent(Settings.ACTION_SETTINGS))
                            }
                        }
                        .setPositiveButton("Clear app cache") { _, _ -> clearOwnTemporaryCache() }
                        .create()
                    dialog.setOnShowListener {
                        dialog.getButton(AlertDialog.BUTTON_NEUTRAL)?.setOnClickListener {
                            try {
                                startActivity(Intent(Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS))
                            } catch (_: Exception) {
                                startActivity(Intent(Settings.ACTION_SETTINGS))
                            }
                        }
                    }
                    dialog.show()
                }
            } catch (error: Exception) {
                runOnUiThread {
                    status.text = "Boost diagnostics failed: " + (error.localizedMessage ?: "unknown error")
                    scanCount.text = "Boost check failed"
                }
            }
        }
    }

    private fun directorySize(directory: File): Long {
        if (!directory.exists()) return 0L
        if (directory.isFile) return directory.length()
        return directory.listFiles()?.sumOf { child -> directorySize(child) } ?: 0L
    }

    private fun clearOwnTemporaryCache() {
        worker.execute {
            var removed = 0L
            fun clearChildren(directory: File?) {
                if (directory == null || !directory.exists()) return
                directory.listFiles()?.forEach { child ->
                    if (child.isDirectory) clearChildren(child)
                    val size = if (child.isFile) child.length() else 0L
                    if (child.delete()) removed += size
                }
            }
            clearChildren(cacheDir)
            clearChildren(externalCacheDir)
            // Ask the runtime to collect only this app's now-unreferenced objects.
            System.gc()
            val freed = removed
            runOnUiThread {
                status.text = "NICE BOOST COMPLETE\n\nRemoved " + Formatter.formatFileSize(this, freed) +
                    " of Nice Antivirus temporary cache. Requested garbage collection for this app only. " +
                    "Android controls system RAM and other apps; no other app was force-stopped and no personal files were deleted."
                scanCount.text = "Own cache cleared • " + Formatter.formatFileSize(this, freed) + " released"
                updateScanProgress(0, 0, 0)
            }
        }
    }

    private fun chooseStorageFolder() {
        startActivityForResult(Intent(Intent.ACTION_OPEN_DOCUMENT_TREE), storageRequest)
    }

    private fun analyzeStorageTree(treeUri: Uri) {
        status.text = "Analyzing selected storage folder…"
        scanCount.text = "Storage analysis running…"
        worker.execute {
            val root = DocumentFile.fromTreeUri(this, treeUri)
            val files = mutableListOf<DocumentFile>()
            var visited = 0
            fun walk(directory: DocumentFile, depth: Int) {
                if (depth > 20 || visited >= 10000) return
                val children = try { directory.listFiles() } catch (_: Exception) { emptyArray() }
                children.forEach { child ->
                    if (visited >= 10000) return@forEach
                    visited++
                    if (child.isDirectory) walk(child, depth + 1)
                    else if (child.isFile) files.add(child)
                }
            }
            if (root != null && root.isDirectory) walk(root, 0)
            val largest = files.sortedByDescending { it.length() }.take(20)
            val junkExtensions = setOf(".tmp", ".temp", ".bak", ".old", ".dmp", ".log")
            val candidates = files.filter { file ->
                val name = (file.name ?: "").lowercase()
                val ext = name.substringAfterLast(".", "").let { if (it.isEmpty()) "" else ".$it" }
                file.length() == 0L || ext in junkExtensions || name == "thumbs.db" || name.endsWith("~")
            }
            val totalBytes = files.sumOf { it.length().coerceAtLeast(0L) }
            val lines = StringBuilder()
            lines.append("FILES FOUND: ").append(files.size).append(if (visited >= 10000) " (scan limit reached)" else "").append("\n")
            lines.append("TOTAL SIZE: ").append(formatBytes(totalBytes)).append("\n")
            lines.append("REVIEW CANDIDATES: ").append(candidates.size).append("\n\n")
            lines.append("LARGEST FILES (top 20)\n")
            largest.forEach { file -> lines.append("• ").append(file.name ?: "Unnamed").append(" — ").append(formatBytes(file.length())).append("\n") }
            lines.append("\nPOSSIBLE JUNK — REVIEW ONLY\n")
            candidates.take(40).forEach { file ->
                val name = file.name ?: "Unnamed"
                val reason = if (file.length() == 0L) "empty file" else "temporary/backup/log-like filename"
                lines.append("• ").append(name).append(" — ").append(formatBytes(file.length())).append(" (").append(reason).append(")\n")
            }
            if (candidates.size > 40) lines.append("…and ").append(candidates.size - 40).append(" more candidates\n")
            lines.append("\nNothing was deleted. Review candidates manually; logs and backups may contain important data. .bin files are not treated as junk by extension alone.")
            runOnUiThread {
                scanCount.text = files.size.toString() + " files analyzed • " + candidates.size + " review candidates"
                status.text = "STORAGE ANALYSIS\n\n" + lines.toString()
            }
        }
    }

    private fun formatBytes(bytes: Long): String {
        if (bytes < 1024L) return "$bytes B"
        val units = arrayOf("KB", "MB", "GB", "TB")
        var value = bytes.toDouble()
        var index = -1
        do { value /= 1024.0; index++ } while (value >= 1024.0 && index < units.lastIndex)
        return String.format(java.util.Locale.US, "%.2f %s", value, units[index])
    }

    private fun showDeviceHealth() {
        try {
            val manager = getSystemService(ACTIVITY_SERVICE) as ActivityManager
            val memory = ActivityManager.MemoryInfo()
            manager.getMemoryInfo(memory)
            val stat = StatFs(filesDir.absolutePath)
            val total = stat.totalBytes
            val available = stat.availableBytes
            val used = (total - available).coerceAtLeast(0L)
            status.text = "DEVICE HEALTH\n\n" +
                "RAM total: " + Formatter.formatFileSize(this, memory.totalMem) + "\n" +
                "RAM available: " + Formatter.formatFileSize(this, memory.availMem) + "\n" +
                "Low-memory state: " + memory.lowMemory + "\n\n" +
                "App data volume total: " + Formatter.formatFileSize(this, total) + "\n" +
                "App data volume used: " + Formatter.formatFileSize(this, used) + "\n" +
                "App data volume available: " + Formatter.formatFileSize(this, available) + "\n\n" +
                "Android does not allow ordinary apps to clear other apps private caches or force-free their RAM. Storage figures above describe the volume containing this app; choose a shared folder in Storage Analyzer for user-file analysis."
            scanCount.text = if (memory.lowMemory) "System reports low memory" else "Device memory status updated"
        } catch (error: Exception) {
            status.text = "Device health check failed: " + (error.localizedMessage ?: "unknown error")
        }
    }

    private fun updateVirusDatabase() {
        status.text = "Checking signed virus database update…"
        scanCount.text = "Secure update check running…"
        worker.execute {
            try {
                val result = Python.getInstance().getModule("antivirus.updater")
                    .callAttr("update_database", File(filesDir, "signatures.db").absolutePath).toString()
                runOnUiThread {
                    status.text = "VIRUS DATABASE UPDATE\n\n" + result
                    scanCount.text = "Database update finished"
                }
            } catch (error: Exception) {
                val message = error.localizedMessage ?: "unknown error"
                runOnUiThread {
                    status.text = "SECURE UPDATE NOT AVAILABLE\n\n" + message +
                        "\n\nUpdates remain disabled until the official HTTPS manifest URL and publisher public key are configured. No unverified database was installed."
                    scanCount.text = "Update not installed"
                }
            }
        }
    }

    private fun showQuarantine() {
        val folder = File(filesDir, "quarantine")
        val items = folder.listFiles()?.filter { it.isFile && !it.name.endsWith(".meta") }.orEmpty()
        if (items.isEmpty()) {
            status.text = "Quarantine is empty. Detected files can be copied here after a scan."
            return
        }
        val labels = items.map { file ->
            val meta = File(file.absolutePath + ".meta")
            val original = if (meta.exists()) meta.readText() else file.name
            original + "  (" + file.length() + " bytes)"
        }.toTypedArray()
        AlertDialog.Builder(this)
            .setTitle("Quarantine • " + items.size + " item(s)")
            .setItems(labels) { _, index ->
                val selected = items[index]
                AlertDialog.Builder(this)
                    .setTitle("Restore quarantined copy?")
                    .setMessage("This exports a copy to a location you choose. It does not verify the file is safe. Do not install or open a detected file unless you are certain it is safe.")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Export copy") { _, _ ->
                        restoreFile = selected
                        val meta = File(selected.absolutePath + ".meta")
                        val original = if (meta.exists()) meta.readText() else selected.name
                        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                            addCategory(Intent.CATEGORY_OPENABLE)
                            type = "*/*"
                            putExtra(Intent.EXTRA_TITLE, original.substringAfterLast('/').take(120))
                        }
                        startActivityForResult(intent, restoreRequest)
                    }
                    .setNeutralButton("Delete quarantine copy") { _, _ ->
                        selected.delete()
                        File(selected.absolutePath + ".meta").delete()
                        status.text = "Quarantine copy deleted. Original source was not changed."
                    }
                    .show()
            }
            .setNegativeButton("Close", null)
            .show()
    }

    @Suppress("DEPRECATION")
    private fun inspectApkPermissions(apkFile: File): String {
        return try {
            val flags = PackageManager.GET_PERMISSIONS or PackageManager.GET_SERVICES
            val info = if (Build.VERSION.SDK_INT >= 33) {
                packageManager.getPackageArchiveInfo(apkFile.absolutePath,
                    PackageManager.PackageInfoFlags.of(flags.toLong()))
            } else {
                packageManager.getPackageArchiveInfo(apkFile.absolutePath, flags)
            } ?: return "\nAPK permission review: manifest could not be parsed by Android."
            val permissions = info.requestedPermissions?.toList().orEmpty()
            val sensitive = mapOf(
                "android.permission.READ_SMS" to "SMS reading",
                "android.permission.RECEIVE_SMS" to "SMS receiving",
                "android.permission.SEND_SMS" to "SMS sending",
                "android.permission.READ_CONTACTS" to "Contacts access",
                "android.permission.READ_CALL_LOG" to "Call-log access",
                "android.permission.RECORD_AUDIO" to "Microphone recording",
                "android.permission.CAMERA" to "Camera access",
                "android.permission.ACCESS_FINE_LOCATION" to "Precise location",
                "android.permission.ACCESS_BACKGROUND_LOCATION" to "Background location",
                "android.permission.REQUEST_INSTALL_PACKAGES" to "Installing other APKs",
                "android.permission.SYSTEM_ALERT_WINDOW" to "Draw over other apps",
                "android.permission.READ_PHONE_STATE" to "Phone-state access"
            )
            val risky = permissions.mapNotNull { permission ->
                sensitive[permission]?.let { it + " (" + permission.substringAfterLast('.') + ")" }
            }
            val serviceWarnings = info.services?.filter {
                it.permission == "android.permission.BIND_ACCESSIBILITY_SERVICE" ||
                    it.permission == "android.permission.BIND_DEVICE_ADMIN"
            }?.map { it.permission ?: "special service" }.orEmpty()
            val output = StringBuilder("\nAPK permission review: ")
            output.append(permissions.size).append(" declared permission(s).")
            if (risky.isNotEmpty()) {
                output.append("\nSensitive permissions: ").append(risky.joinToString(", "))
            } else {
                output.append("\nNo permissions from the app's sensitive-permission watchlist.")
            }
            if (serviceWarnings.isNotEmpty()) {
                output.append("\nSpecial service declarations: ").append(serviceWarnings.distinct().joinToString(", "))
            }
            output.append("\nNote: permissions indicate capability, not proof of malicious behavior.")
            output.toString()
        } catch (error: Exception) {
            "\nAPK permission review unavailable: " + (error.localizedMessage ?: "parse error")
        }
    }

    private fun chooseFileForRepair() {
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
            putExtra(Intent.EXTRA_TITLE, "Select a damaged or unreadable file")
        }
        startActivityForResult(intent, fileRepairRequest)
    }

    private fun repairSelectedDocument(uri: Uri) {
        val displayName = queryDisplayName(uri) ?: "selected_file"
        status.text = "Analyzing file structure: " + displayName
        scanCount.text = "Python repair engine running…"
        worker.execute {
            var tempInput: File? = null
            try {
                val inputDir = File(cacheDir, "repair-input").apply { mkdirs() }
                val safeName = displayName.replace(Regex("[^A-Za-z0-9._-]"), "_").take(100)
                val inputCopy = File.createTempFile("repair_", "_" + safeName, inputDir)
                tempInput = inputCopy
                contentResolver.openInputStream(uri)?.use { input ->
                    inputCopy.outputStream().use { output -> input.copyTo(output) }
                } ?: throw IllegalStateException("Selected file cannot be opened")
                val outputDir = File(cacheDir, "repaired").apply { mkdirs() }
                val json = Python.getInstance().getModule("antivirus.file_repair")
                    .callAttr("repair_json", inputCopy.absolutePath, outputDir.absolutePath).toString()
                val report = org.json.JSONObject(json)
                val type = report.optString("type", "Unknown")
                val action = report.optString("action", "inspect_only")
                val details = report.optJSONArray("details")
                val explanation = StringBuilder()
                if (details != null) {
                    for (index in 0 until details.length()) explanation.append("• ")
                        .append(details.optString(index)).append("\n")
                }
                val outputPath = report.optString("output_path", "")
                val output = if (outputPath.isNotBlank()) File(outputPath) else null
                runOnUiThread {
                    status.text = "FILE REPAIR REPORT\n\nFile: " + displayName +
                        "\nType: " + type +
                        "\nSize: " + Formatter.formatFileSize(this, report.optLong("size", 0L)) +
                        "\nSHA-256: " + report.optString("sha256", "unavailable") +
                        "\nAction: " + action.replace('_', ' ') +
                        "\n\n" + explanation.toString() +
                        "\nOriginal file was not modified."
                    scanCount.text = if (output != null && output.isFile) "Repair output ready to export" else "Analysis completed • no repaired copy created"
                    if (output != null && output.isFile && output.length() > 0L) {
                        AlertDialog.Builder(this)
                            .setTitle("Repaired copy ready")
                            .setMessage("A separate output copy was created. Save it to a location you choose? The original file remains unchanged.")
                            .setNegativeButton("Later", null)
                            .setPositiveButton("Save copy") { _, _ ->
                                pendingRepairOutput = output
                                val saveIntent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                                    addCategory(Intent.CATEGORY_OPENABLE)
                                    setType("*/*")
                                    putExtra(Intent.EXTRA_TITLE, output.name)
                                }
                                startActivityForResult(saveIntent, saveRepairRequest)
                            }
                            .show()
                    }
                }
            } catch (error: Exception) {
                runOnUiThread {
                    status.text = "FILE REPAIR FAILED\n\n" + (error.localizedMessage ?: error.javaClass.simpleName)
                    scanCount.text = "Repair analysis failed"
                }
            } finally {
                tempInput?.delete()
            }
        }
    }

    private fun queryDisplayName(uri: Uri): String? {
        if (uri.scheme == "file") return uri.path?.let { File(it).name }
        return try {
            contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val index = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                    if (index >= 0) return cursor.getString(index)
                }
            }
            null
        } catch (e: Exception) { null }
    }


    @Suppress("DEPRECATION")
    private fun scanInstalledApps() {
        status.text = "Checking installed apps visible in the launcher…"
        scanCount.text = "Installed app permission review running…"
        worker.execute {
            val report = mutableListOf<String>()
            var checked = 0
            var flagged = 0
            var grantedSensitive = 0
            val watchlist = mapOf(
                "android.permission.READ_SMS" to "SMS reading",
                "android.permission.RECEIVE_SMS" to "SMS receiving",
                "android.permission.SEND_SMS" to "SMS sending",
                "android.permission.READ_CONTACTS" to "Contacts reading",
                "android.permission.WRITE_CONTACTS" to "Contacts editing",
                "android.permission.READ_CALL_LOG" to "Call-log reading",
                "android.permission.WRITE_CALL_LOG" to "Call-log editing",
                "android.permission.RECORD_AUDIO" to "Microphone",
                "android.permission.CAMERA" to "Camera",
                "android.permission.ACCESS_FINE_LOCATION" to "Precise location",
                "android.permission.ACCESS_COARSE_LOCATION" to "Approximate location",
                "android.permission.ACCESS_BACKGROUND_LOCATION" to "Background location",
                "android.permission.REQUEST_INSTALL_PACKAGES" to "Install unknown apps",
                "android.permission.SYSTEM_ALERT_WINDOW" to "Display over other apps",
                "android.permission.READ_PHONE_STATE" to "Phone state",
                "android.permission.READ_EXTERNAL_STORAGE" to "Read shared storage",
                "android.permission.WRITE_EXTERNAL_STORAGE" to "Write shared storage",
                "android.permission.MANAGE_EXTERNAL_STORAGE" to "Manage all files"
            )
            try {
                val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                val launchables = packageManager.queryIntentActivities(launcherIntent, 0)
                val packageNames = launchables.mapNotNull { it.activityInfo?.packageName }
                    .distinct().filter { it != packageName }.sorted()
                packageNames.forEach { appPackage ->
                    try {
                        val packageInfo = if (Build.VERSION.SDK_INT >= 33) {
                            packageManager.getPackageInfo(
                                appPackage,
                                PackageManager.PackageInfoFlags.of(PackageManager.GET_PERMISSIONS.toLong())
                            )
                        } else {
                            @Suppress("DEPRECATION")
                            packageManager.getPackageInfo(appPackage, PackageManager.GET_PERMISSIONS)
                        }
                        val requested = packageInfo.requestedPermissions.orEmpty()
                        val flags = packageInfo.requestedPermissionsFlags
                        val sensitive = requested.mapIndexedNotNull { index, permission ->
                            val label = watchlist[permission] ?: return@mapIndexedNotNull null
                            val granted = flags != null && index < flags.size &&
                                (flags[index] and PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0
                            if (granted) label else null
                        }
                        val declared = requested.mapNotNull { watchlist[it] }
                        val appLabel = packageInfo.applicationInfo?.loadLabel(packageManager)?.toString() ?: appPackage
                        checked++
                        if (sensitive.isNotEmpty()) {
                            flagged++
                            grantedSensitive += sensitive.size
                        }
                        val details = when {
                            sensitive.isNotEmpty() -> "GRANTED sensitive access: " + sensitive.joinToString(", ")
                            declared.isNotEmpty() -> "Watchlist permissions declared but not currently granted: " +
                                declared.joinToString(", ")
                            else -> "No watchlist permissions declared."
                        }
                        report.add(appLabel + " (" + appPackage + ")\n" + details)
                    } catch (error: Exception) {
                        report.add(appPackage + ": unable to inspect (" + (error.localizedMessage ?: "unknown") + ")")
                    }
                }
            } catch (error: Exception) {
                report.add("Installed-app query failed: " + (error.localizedMessage ?: "unknown error"))
            }
            val summary = report.take(35).joinToString("\n\n")
            runOnUiThread {
                scanCount.text = checked.toString() + " apps checked • " + flagged +
                    " with granted watchlist access"
                status.text = "INSTALLED APP PERMISSION REVIEW\n\n" + summary +
                    if (report.size > 35) "\n\n…and " + (report.size - 35) + " more apps." else ""
                status.append(
                    "\n\nGRANTED access is separated from permissions merely declared in the APK. " +
                    "A permission can be legitimate for an app's function; this report is a privacy review, not a malware verdict. " +
                    "Scope: launcher-visible apps only; hidden/system packages may be omitted."
                )
            }
        }
    }

    private fun showScanHistory() {
        status.text = "Loading recent scan history…"
        worker.execute {
            try {
                val report = Python.getInstance().getModule("antivirus.scanner")
                    .callAttr("scan_history_report", File(filesDir, "signatures.db").absolutePath, 50)
                    .toString()
                runOnUiThread {
                    status.text = report + "\n\nHistory is stored locally in the app database. It records scan status and a short SHA-256 prefix; it does not mean a no-match file is guaranteed safe."
                    scanCount.text = "Recent scan history"
                }
            } catch (error: Exception) {
                runOnUiThread {
                    status.text = "Could not load scan history: " + (error.localizedMessage ?: "unknown error")
                }
            }
        }
    }

    private fun showDuplicateContentReview() {
        status.text = "Checking repeated SHA-256 records…"
        worker.execute {
            try {
                val report = Python.getInstance().getModule("antivirus.scanner")
                    .callAttr("duplicate_content_report", File(filesDir, "signatures.db").absolutePath, 200)
                    .toString()
                runOnUiThread {
                    status.text = report + "\n\nThis is a read-only review of the latest 200 saved scan records, not a full-device duplicate search."
                    scanCount.text = "Repeated content review"
                }
            } catch (error: Exception) {
                runOnUiThread {
                    status.text = "Could not review repeated content: " + (error.localizedMessage ?: "unknown error")
                }
            }
        }
    }

    private fun confirmClearScanHistory() {
        AlertDialog.Builder(this)
            .setTitle("Clear scan history?")
            .setMessage("This permanently removes only saved scan-history records from this app. Virus signatures, signature database version, and quarantined files will NOT be deleted. Export the report first if you need a copy.")
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Clear history") { _, _ ->
                status.text = "Clearing scan history…"
                worker.execute {
                    try {
                        val removed = Python.getInstance().getModule("antivirus.scanner")
                            .callAttr("clear_scan_history_records", File(filesDir, "signatures.db").absolutePath)
                            .toInt()
                        runOnUiThread {
                            status.text = "Scan history cleared. " + removed + " record(s) removed. Signatures and quarantine were preserved."
                            scanCount.text = "Scan history empty"
                        }
                    } catch (error: Exception) {
                        runOnUiThread {
                            status.text = "Could not clear scan history: " + (error.localizedMessage ?: "unknown error")
                        }
                    }
                }
            }
            .show()
    }

    private fun exportScanHistory() {
        val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "text/plain"
            putExtra(Intent.EXTRA_TITLE, "NiceAntivirus_Scan_History.txt")
        }
        startActivityForResult(intent, exportHistoryRequest)
    }


    private fun runToolDiagnostics() {
        status.text = "Running safe tool diagnostics…"
        scanCount.text = "Tool checks running"
        worker.execute {
            val report = try {
                Python.getInstance().getModule("antivirus.scanner")
                    .callAttr("diagnostics_report").toString()
            } catch (error: Exception) {
                "NICE ANTIVIRUS — TOOL DIAGNOSTICS\\n[FAIL] Python diagnostics — " +
                    (error.localizedMessage ?: "unknown error")
            }
            val usage = if (hasUsageAccess()) "[PASS] Android Usage Access — granted"
                else "[WARNING] Android Usage Access — permission not granted"
            val notifications = if (Build.VERSION.SDK_INT < 33 ||
                checkSelfPermission(android.Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED) {
                "[PASS] Notification runtime permission — granted or not required"
            } else {
                "[WARNING] Notification runtime permission — not granted"
            }
            val scheduled = try {
                val infos = WorkManager.getInstance(this)
                    .getWorkInfosForUniqueWork(AppActivityMonitorWorker.UNIQUE_WORK_NAME).get()
                if (infos.any { !it.state.isFinished }) "[PASS] Scheduled app monitor — work is enqueued"
                else "[WARNING] Scheduled app monitor — no active scheduled work"
            } catch (error: Exception) {
                "[WARNING] Scheduled app monitor — status unavailable"
            }
            runOnUiThread {
                status.text = report + "\\n" + usage + "\\n" + notifications + "\\n" + scheduled +
                    "\\n\\nPASS means the tested code path worked. WARNING means setup is missing or the feature is not configured. FAIL means a self-test failed."
                scanCount.text = "Diagnostics completed"
            }
        }
    }

    private fun runSelfCheck() {
        try {
            status.text = Python.getInstance().getModule("antivirus.scanner")
                .callAttr("engine_self_check").toString()
        } catch (error: Exception) {
            status.text = "Engine check failed: " + (error.localizedMessage ?: "unknown error")
        }
    }

    private fun matchWrap() = LinearLayout.LayoutParams(
        ViewGroup.LayoutParams.MATCH_PARENT,
        ViewGroup.LayoutParams.WRAP_CONTENT
    )

    override fun onDestroy() {
        worker.shutdown()
        super.onDestroy()
    }
}
