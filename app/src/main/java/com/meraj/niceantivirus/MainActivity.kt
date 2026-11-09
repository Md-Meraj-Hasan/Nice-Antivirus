package com.meraj.niceantivirus

import android.app.Activity
import android.app.AlertDialog
import android.app.ActivityManager
import android.app.AppOpsManager
import android.app.usage.UsageStatsManager
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Build
import android.net.Uri
import android.os.Bundle
import android.os.StatFs
import android.provider.Settings
import android.text.format.Formatter
import android.graphics.Color
import android.view.Gravity
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
    private var restoreFile: File? = null
    private var refreshPermissionsOnResume = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!Python.isStarted()) Python.start(AndroidPlatform(this))
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(24, 32, 24, 32)
            setBackgroundColor(Color.rgb(12, 19, 27))
        }
        val hero = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            gravity = Gravity.CENTER
            setPadding(20, 28, 20, 28)
            setBackgroundColor(Color.rgb(23, 39, 49))
        }
        hero.addView(TextView(this).apply {
            text = "NICE ANTIVIRUS"
            textSize = 27f
            gravity = Gravity.CENTER
            setTextColor(Color.WHITE)
        }, matchWrap())
        hero.addView(TextView(this).apply {
            text = "SMART MOBILE SECURITY"
            textSize = 12f
            gravity = Gravity.CENTER
            setTextColor(Color.rgb(40, 210, 125))
            setPadding(0, 10, 0, 0)
        }, matchWrap())
        content.addView(hero, matchWrap())
        scanCount = TextView(this).apply {
            text = "0 files scanned  •  0 threats matched"
            textSize = 14f
            gravity = Gravity.CENTER
            setTextColor(Color.rgb(40, 210, 125))
            setPadding(0, 24, 0, 12)
        }
        content.addView(scanCount, matchWrap())
        status = TextView(this).apply {
            text = "Protection engine ready. Select a file, APK, folder or SD card."
            textSize = 14f
            setTextColor(Color.WHITE)
            setPadding(16, 18, 16, 18)
            setBackgroundColor(Color.rgb(25, 34, 44))
        }
        content.addView(status, matchWrap())
        addButton(content, "SCAN FILE / APK") { chooseFile() }
        addButton(content, "SCAN FOLDER / SD CARD") { chooseFolder() }
        addButton(content, "SCAN INSTALLED APPS") { scanInstalledApps() }
        addButton(content, "ANALYZE STORAGE / JUNK") { chooseStorageFolder() }
        addButton(content, "RAM & STORAGE STATUS") { showDeviceHealth() }
        addButton(content, "PERFORMANCE ASSIST") { runPerformanceAssist() }
        addButton(content, "BACKGROUND APP MANAGER") { showBackgroundAppManager() }
        addButton(content, "PERMISSION SETUP") { showPermissionSetup() }
        addButton(content, "APP ACTIVITY MONITOR") { showAppActivityMonitor() }
        addButton(content, "IMPORTANT APPS IGNORE LIST") { showImportantAppsIgnoreList() }
        addButton(content, "START AUTOMATIC MONITORING") { startScheduledMonitoring() }
        addButton(content, "STOP AUTOMATIC MONITORING") { stopScheduledMonitoring() }
        addButton(content, "ENGINE SELF-CHECK") { runSelfCheck() }
        addButton(content, "QUARANTINE / RESTORE") { showQuarantine() }
        addButton(content, "VIRUS DATABASE UPDATE") { updateVirusDatabase() }
        content.addView(TextView(this).apply {
            text = "Safety note: no files are automatically deleted. A clean result means no match in the installed signature database, not a guarantee that a file is safe."
            textSize = 12f
            setTextColor(Color.LTGRAY)
            setPadding(4, 20, 4, 8)
        }, matchWrap())
        setContentView(ScrollView(this).apply { addView(content) })
    }


    override fun onResume() {
        super.onResume()
        if (refreshPermissionsOnResume) {
            refreshPermissionsOnResume = false
            showPermissionSetup()
        }
    }

    private fun addButton(parent: LinearLayout, label: String, action: () -> Unit) {
        parent.addView(Button(this).apply {
            text = label
            isAllCaps = false
            setOnClickListener { action() }
        }, matchWrap().apply { topMargin = 10 })
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

    private fun scanUris(uris: List<Uri>) {
        runOnUiThread {
            status.text = "Preparing scan of " + uris.size + " item(s)…"
            scanCount.text = "Scanning…"
        }
        worker.execute {
            val results = mutableListOf<String>()
            val detectedTemps = mutableListOf<Pair<String, File>>()
            var threats = 0
            val python = Python.getInstance().getModule("antivirus.scanner")
            val cache = File(cacheDir, "scan")
            cache.mkdirs()
            uris.forEachIndexed { index, uri ->
                try {
                    val name = queryDisplayName(uri) ?: "selected_file"
                    val safeName = name.replace(Regex("[^A-Za-z0-9._-]"), "_").take(100)
                    val temp = File.createTempFile("scan_", "_" + safeName, cache)
                    contentResolver.openInputStream(uri)?.use { input ->
                        temp.outputStream().use { output -> input.copyTo(output) }
                    } ?: throw IllegalStateException("Cannot open selected document")
                    val result = python.callAttr("scan_local_file", temp.absolutePath, File(filesDir, "signatures.db").absolutePath).toString()
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
                val done = index + 1
                runOnUiThread { scanCount.text = done.toString() + " / " + uris.size + " scanned  •  " + threats + " threat matches" }
            }
            val summary = results.take(40).joinToString("\n\n")
            runOnUiThread {
                status.text = "SCAN FINISHED\n\n" + summary +
                    if (results.size > 40) "\n\n…and " + (results.size - 40) + " more items." else ""
                scanCount.text = results.size.toString() + " files scanned  •  " + threats + " threat matches"
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
                    records.joinToString("\\n\\n") { item ->
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
                        (if (item.first in protectedPackages) "★ PROTECTED APP\\n" else "") + "$label\\nPackage: ${item.first}\\nForeground use: ${minutes} min\\nLast used: $last"
                    }
                }
                runOnUiThread {
                    scanCount.text = records.size.toString() + " apps with usage records • last 24 hours"
                    status.text = "APP ACTIVITY MONITOR • LAST 24 HOURS\\n\\n" + report +
                        "\\n\\nImportant: usage history is not a live running-process list. It cannot identify downloads, uploads or background work, and it must never be used alone to force-stop an app."
                }
            } catch (error: Exception) {
                runOnUiThread {
                    status.text = "App activity review failed: " + (error.localizedMessage ?: "unknown error") +
                        "\\nCheck Usage Access in Permission Setup."
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
                val labels = apps.map { it.second + "\\n" + it.first }.toTypedArray()
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
                            status.text = "IMPORTANT APPS IGNORE LIST\\n\\nSaved ${protected.size} protected app(s). These apps will be marked as protected in the activity report and excluded from future Nice Antivirus app-management recommendations. Android itself may still manage apps normally."
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
        status.text = "AUTOMATIC APP ACTIVITY MONITOR SCHEDULED\\n\\nWorkManager checks usage changes periodically, with a 15-minute minimum interval. Android may defer work because of Doze mode, battery restrictions or device policy. " +
            (if (notificationsAllowed) "Activity summaries can appear as notifications." else "Notifications are currently not permitted; enable them in Permission Setup to receive alerts.") +
            "\\n\\nThis reports foreground app usage changes only. It does not detect malware, downloads, uploads or background processes, and it never closes apps."
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
        val report = "NICE ANTIVIRUS • PERMISSION CENTER\\n\\n" +
            "Usage Access: " + (if (usageGranted) "GRANTED" else "NOT GRANTED") + "\\n" +
            "Notifications: " + (if (notificationsEnabled) "ENABLED" else if (!notificationGranted) "PERMISSION NOT GRANTED" else "BLOCKED IN APP SETTINGS") + "\\n" +
            "Battery optimization: " + (if (Build.VERSION.SDK_INT < 23) "NOT APPLICABLE" else if (batteryOptimized) "ACTIVE (background work may be delayed)" else "IGNORED FOR THIS APP") + "\\n" +
            "Scheduled monitor: " + (if (monitorEnabled) "ENABLED" else "DISABLED") + "\\n\\n" +
            "Usage Access supports recent foreground-usage reports. It cannot identify downloads/uploads, prove malware or force-stop apps.\\n\\n" +
            "Notifications are optional alerts. Battery optimization can delay scheduled checks; exempting this app is optional and may increase battery use.\\n\\n" +
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
                status.text = "BACKGROUND APP MANAGER\\n\\nChoose an app to open its Android App Info page. Android will let you decide whether to force stop it."
                if (sorted.isEmpty()) {
                    status.append("\\nNo launcher apps were found.")
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
        status.text = "Checking device performance…"
        scanCount.text = "Performance diagnostics running…"
        worker.execute {
            try {
                val activityManager = getSystemService(ACTIVITY_SERVICE) as ActivityManager
                val memory = ActivityManager.MemoryInfo()
                activityManager.getMemoryInfo(memory)
                val dataStat = StatFs(android.os.Environment.getDataDirectory().absolutePath)
                val freeBytes = dataStat.availableBytes
                val totalBytes = dataStat.totalBytes
                val freePercent = if (totalBytes > 0L) (freeBytes * 100.0 / totalBytes) else 0.0
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
                } else "Not available on this Android version"
                val advice = mutableListOf<String>()
                if (memory.lowMemory || memory.availMem < 200L * 1024L * 1024L) advice.add("RAM is low: close unused apps using Android Recent Apps; avoid running many heavy apps together.")
                if (freePercent < 10.0) advice.add("Storage is critically low: review large downloads/photos and uninstall apps you no longer use.")
                else if (freePercent < 20.0) advice.add("Storage is getting low: keep more free space for smooth app updates and temporary files.")
                if (thermal == "Severe" || thermal == "Critical" || thermal == "Emergency" || thermal == "Shutdown risk") advice.add("Device is hot: stop heavy tasks, unplug charging if safe, and let it cool in a ventilated place.")
                if (advice.isEmpty()) advice.add("No major low-memory, low-storage or thermal warning was reported by Android. Slowness can still be caused by a specific app, old hardware or background activity.")
                val report = "PERFORMANCE CHECK\\n\\n" +
                    "Available RAM: " + Formatter.formatFileSize(this, memory.availMem) + " / " + Formatter.formatFileSize(this, memory.totalMem) + "\\n" +
                    "System low-memory flag: " + memory.lowMemory + "\\n" +
                    "Free internal storage: " + Formatter.formatFileSize(this, freeBytes) + " (" + String.format(java.util.Locale.US, "%.1f", freePercent) + "%)\\n" +
                    "Nice Antivirus temporary cache: " + Formatter.formatFileSize(this, cacheBytes) + "\\n" +
                    "Device thermal status: " + thermal + "\\n\\nRECOMMENDATIONS\\n• " + advice.joinToString("\\n• ") +
                    "\\n\\nOnly Nice Antivirus temporary cache can be cleared here. Other apps data/cache and system processes are not touched."
                runOnUiThread {
                    status.text = report
                    scanCount.text = "Performance check complete"
                    AlertDialog.Builder(this)
                        .setTitle("Performance check complete")
                        .setMessage("Nice Antivirus temporary cache: " + Formatter.formatFileSize(this, cacheBytes) + ". Clear only these temporary files? Your scans, quarantine, signatures and personal files will be kept.")
                        .setNegativeButton("Keep cache", null)
                        .setPositiveButton("Clear app temp cache") { _, _ -> clearOwnTemporaryCache() }
                        .show()
                }
            } catch (error: Exception) {
                runOnUiThread { status.text = "Performance check failed: " + (error.localizedMessage ?: "unknown error") }
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
            runOnUiThread {
                status.text = "PERFORMANCE CLEANUP COMPLETE\\n\\nRemoved " + Formatter.formatFileSize(this, removed) + " from Nice Antivirus temporary cache only. Your personal files, quarantine, signature database and other apps were not changed."
                scanCount.text = "App temporary cache cleaned"
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
            lines.append("FILES FOUND: ").append(files.size).append(if (visited >= 10000) " (scan limit reached)" else "").append("\\n")
            lines.append("TOTAL SIZE: ").append(formatBytes(totalBytes)).append("\\n")
            lines.append("REVIEW CANDIDATES: ").append(candidates.size).append("\\n\\n")
            lines.append("LARGEST FILES (top 20)\\n")
            largest.forEach { file -> lines.append("• ").append(file.name ?: "Unnamed").append(" — ").append(formatBytes(file.length())).append("\\n") }
            lines.append("\\nPOSSIBLE JUNK — REVIEW ONLY\\n")
            candidates.take(40).forEach { file ->
                val name = file.name ?: "Unnamed"
                val reason = if (file.length() == 0L) "empty file" else "temporary/backup/log-like filename"
                lines.append("• ").append(name).append(" — ").append(formatBytes(file.length())).append(" (").append(reason).append(")\\n")
            }
            if (candidates.size > 40) lines.append("…and ").append(candidates.size - 40).append(" more candidates\\n")
            lines.append("\\nNothing was deleted. Review candidates manually; logs and backups may contain important data. .bin files are not treated as junk by extension alone.")
            runOnUiThread {
                scanCount.text = files.size.toString() + " files analyzed • " + candidates.size + " review candidates"
                status.text = "STORAGE ANALYSIS\\n\\n" + lines.toString()
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
            status.text = "DEVICE HEALTH\\n\\n" +
                "RAM total: " + Formatter.formatFileSize(this, memory.totalMem) + "\\n" +
                "RAM available: " + Formatter.formatFileSize(this, memory.availMem) + "\\n" +
                "Low-memory state: " + memory.lowMemory + "\\n\\n" +
                "App data volume total: " + Formatter.formatFileSize(this, total) + "\\n" +
                "App data volume used: " + Formatter.formatFileSize(this, used) + "\\n" +
                "App data volume available: " + Formatter.formatFileSize(this, available) + "\\n\\n" +
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
                    status.text = "VIRUS DATABASE UPDATE\\n\\n" + result
                    scanCount.text = "Database update finished"
                }
            } catch (error: Exception) {
                val message = error.localizedMessage ?: "unknown error"
                runOnUiThread {
                    status.text = "SECURE UPDATE NOT AVAILABLE\\n\\n" + message +
                        "\\n\\nUpdates remain disabled until the official HTTPS manifest URL and publisher public key are configured. No unverified database was installed."
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

    private fun queryDisplayName(uri: Uri): String? {
        contentResolver.query(uri, arrayOf(android.provider.OpenableColumns.DISPLAY_NAME), null, null, null)
            ?.use { cursor ->
                if (cursor.moveToFirst()) {
                    val index = cursor.getColumnIndex(android.provider.OpenableColumns.DISPLAY_NAME)
                    if (index >= 0) return cursor.getString(index)
                }
            }
        return null
    }


    @Suppress("DEPRECATION")
    private fun scanInstalledApps() {
        status.text = "Checking installed apps visible in the launcher…"
        scanCount.text = "Installed app scan running…"
        worker.execute {
            val report = mutableListOf<String>()
            var checked = 0
            var flagged = 0
            val watchlist = mapOf(
                "android.permission.READ_SMS" to "READ_SMS",
                "android.permission.RECEIVE_SMS" to "RECEIVE_SMS",
                "android.permission.SEND_SMS" to "SEND_SMS",
                "android.permission.READ_CONTACTS" to "READ_CONTACTS",
                "android.permission.READ_CALL_LOG" to "READ_CALL_LOG",
                "android.permission.RECORD_AUDIO" to "RECORD_AUDIO",
                "android.permission.CAMERA" to "CAMERA",
                "android.permission.ACCESS_FINE_LOCATION" to "FINE_LOCATION",
                "android.permission.ACCESS_BACKGROUND_LOCATION" to "BACKGROUND_LOCATION",
                "android.permission.REQUEST_INSTALL_PACKAGES" to "INSTALL_PACKAGES",
                "android.permission.SYSTEM_ALERT_WINDOW" to "OVERLAY",
                "android.permission.READ_PHONE_STATE" to "PHONE_STATE"
            )
            try {
                val launcherIntent = Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER)
                val launchables = packageManager.queryIntentActivities(launcherIntent, 0)
                val packageNames = launchables.mapNotNull { it.activityInfo?.packageName }.distinct()
                packageNames.forEach { packageName ->
                    try {
                        val packageInfo = packageManager.getPackageInfo(packageName, PackageManager.GET_PERMISSIONS)
                        val permissions = packageInfo.requestedPermissions?.toSet().orEmpty()
                        val sensitive = permissions.mapNotNull { watchlist[it] }
                        val label = packageInfo.applicationInfo?.loadLabel(packageManager)?.toString() ?: packageName
                        checked++
                        if (sensitive.isNotEmpty()) flagged++
                        report.add(label + " (" + packageName + ")\n" +
                            if (sensitive.isEmpty()) "No watchlist permissions declared."
                            else "Sensitive permissions declared: " + sensitive.joinToString(", "))
                    } catch (error: Exception) {
                        report.add(packageName + ": unable to inspect (" + (error.localizedMessage ?: "unknown") + ")")
                    }
                }
            } catch (error: Exception) {
                report.add("Installed-app query failed: " + (error.localizedMessage ?: "unknown error"))
            }
            val summary = report.take(35).joinToString("\n\n")
            runOnUiThread {
                scanCount.text = checked.toString() + " launcher apps checked • " + flagged + " with watchlist permissions"
                status.text = "INSTALLED APP REVIEW\n\n" + summary +
                    if (report.size > 35) "\n\n…and " + (report.size - 35) + " more apps." else ""
                status.append("\n\nScope: apps with launcher icons visible to this app. Hidden/system packages may not be included. Permission presence is not proof of malware.")
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
