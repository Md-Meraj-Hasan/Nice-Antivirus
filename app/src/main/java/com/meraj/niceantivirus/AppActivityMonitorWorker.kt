package com.meraj.niceantivirus

import android.app.AppOpsManager
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.usage.UsageStatsManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.app.NotificationCompat
import androidx.core.app.NotificationManagerCompat
import androidx.core.content.ContextCompat
import androidx.work.Worker
import androidx.work.WorkerParameters

/**
 * Periodic, privacy-preserving usage change monitor.
 * This reports foreground-use changes only; it is not malware or background-process detection.
 */
class AppActivityMonitorWorker(
    context: Context,
    params: WorkerParameters
) : Worker(context, params) {

    override fun doWork(): Result {
        if (!hasUsageAccess()) return Result.success()

        return try {
            val now = System.currentTimeMillis()
            val dayStart = java.time.LocalDate.now()
                .atStartOfDay(java.time.ZoneId.systemDefault())
                .toInstant().toEpochMilli()
            val usageManager = applicationContext.getSystemService(Context.USAGE_STATS_SERVICE) as UsageStatsManager
            val stats = usageManager.queryUsageStats(
                UsageStatsManager.INTERVAL_DAILY,
                dayStart,
                now
            ).orEmpty()

            val totals = stats.groupBy { it.packageName }
                .mapValues { (_, rows) -> rows.sumOf { it.totalTimeInForeground } }

            val prefs = applicationContext.getSharedPreferences(PREFS, Context.MODE_PRIVATE)
            val protected = prefs.getStringSet(IGNORE_LIST, emptySet()).orEmpty()
            val baselineExists = prefs.getBoolean(BASELINE_READY, false)
            val newlyUsed = mutableListOf<Pair<String, Long>>()

            totals.forEach { (pkg, total) ->
                if (pkg == applicationContext.packageName) return@forEach
                val key = USAGE_PREFIX + pkg
                val previous = prefs.getLong(key, -1L)
                if (baselineExists && pkg !in protected) {
                    val delta = if (previous < 0L) total else (total - previous).coerceAtLeast(0L)
                    if (delta >= MIN_FOREGROUND_DELTA_MS) newlyUsed.add(pkg to delta)
                }
            }

            val editor = prefs.edit()
            totals.forEach { (pkg, total) -> editor.putLong(USAGE_PREFIX + pkg, total) }
            editor.putBoolean(BASELINE_READY, true).apply()

            if (newlyUsed.isNotEmpty()) postNotification(newlyUsed)
            Result.success()
        } catch (_: SecurityException) {
            Result.success()
        } catch (_: Exception) {
            Result.retry()
        }
    }

    private fun hasUsageAccess(): Boolean {
        return try {
            val appOps = applicationContext.getSystemService(Context.APP_OPS_SERVICE) as AppOpsManager
            val mode = if (Build.VERSION.SDK_INT >= 29) {
                appOps.unsafeCheckOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    android.os.Process.myUid(),
                    applicationContext.packageName
                )
            } else {
                @Suppress("DEPRECATION")
                appOps.checkOpNoThrow(
                    AppOpsManager.OPSTR_GET_USAGE_STATS,
                    android.os.Process.myUid(),
                    applicationContext.packageName
                )
            }
            mode == AppOpsManager.MODE_ALLOWED
        } catch (_: Exception) {
            false
        }
    }

    private fun postNotification(activity: List<Pair<String, Long>>) {
        if (Build.VERSION.SDK_INT >= 33 &&
            ContextCompat.checkSelfPermission(
                applicationContext,
                android.Manifest.permission.POST_NOTIFICATIONS
            ) != PackageManager.PERMISSION_GRANTED
        ) return
        if (!NotificationManagerCompat.from(applicationContext).areNotificationsEnabled()) return

        val manager = applicationContext.getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
        if (Build.VERSION.SDK_INT >= 26) {
            manager.createNotificationChannel(
                NotificationChannel(
                    CHANNEL_ID,
                    "App activity monitoring",
                    NotificationManager.IMPORTANCE_DEFAULT
                ).apply {
                    description = "Periodic summary of recently used apps"
                }
            )
        }

        val names = activity.sortedByDescending { it.second }.take(3).map { (pkg, _) ->
            try {
                val appInfo = if (Build.VERSION.SDK_INT >= 33) {
                    applicationContext.packageManager.getApplicationInfo(
                        pkg,
                        PackageManager.ApplicationInfoFlags.of(0)
                    )
                } else {
                    @Suppress("DEPRECATION")
                    applicationContext.packageManager.getApplicationInfo(pkg, 0)
                }
                applicationContext.packageManager.getApplicationLabel(appInfo).toString()
            } catch (_: Exception) {
                pkg
            }
        }
        val count = activity.size
        val text = names.joinToString(", ") +
            if (count > names.size) " and ${count - names.size} more" else ""
        try {
            NotificationManagerCompat.from(applicationContext).notify(
                NOTIFICATION_ID,
                NotificationCompat.Builder(applicationContext, CHANNEL_ID)
                    .setSmallIcon(android.R.drawable.ic_dialog_info)
                    .setContentTitle("Nice Antivirus • App activity")
                    .setContentText(text)
                    .setStyle(NotificationCompat.BigTextStyle().bigText(
                        "New foreground app usage was recorded: $text. This is an activity summary, not a malware warning."
                    ))
                    .setPriority(NotificationCompat.PRIORITY_DEFAULT)
                    .setAutoCancel(true)
                    .build()
            )
        } catch (_: SecurityException) {
            // Notification permission may have been revoked after the check.
        }
    }

    companion object {
        const val UNIQUE_WORK_NAME = "nice_antivirus_app_activity_monitor"
        private const val PREFS = "nice_antivirus_settings"
        private const val IGNORE_LIST = "important_apps_ignore"
        private const val BASELINE_READY = "activity_monitor_baseline_ready"
        private const val USAGE_PREFIX = "activity_monitor_usage_"
        private const val CHANNEL_ID = "app_activity_monitor"
        private const val NOTIFICATION_ID = 7301
        private const val MIN_FOREGROUND_DELTA_MS = 30_000L
    }
}
