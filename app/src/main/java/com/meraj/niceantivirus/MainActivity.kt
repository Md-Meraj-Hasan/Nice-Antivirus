package com.meraj.niceantivirus

import android.app.Activity
import android.content.Intent
import android.net.Uri
import android.os.Bundle
import android.graphics.Color
import android.view.Gravity
import android.view.ViewGroup
import android.widget.Button
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.TextView
import androidx.documentfile.provider.DocumentFile
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import java.io.File
import java.util.concurrent.Executors

class MainActivity : Activity() {
    private lateinit var status: TextView
    private lateinit var scanCount: TextView
    private val worker = Executors.newSingleThreadExecutor()
    private val pickFileRequest = 4101
    private val pickFolderRequest = 4102

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
        addButton(content, "ENGINE SELF-CHECK") { runSelfCheck() }
        addButton(content, "VIRUS DATABASE UPDATE") {
            status.text = "Updater framework is available. Live updates are not enabled until the trusted publisher key and official HTTPS manifest URL are configured."
        }
        content.addView(TextView(this).apply {
            text = "Safety note: no files are automatically deleted. A clean result means no match in the installed signature database, not a guarantee that a file is safe."
            textSize = 12f
            setTextColor(Color.LTGRAY)
            setPadding(4, 20, 4, 8)
        }, matchWrap())
        setContentView(ScrollView(this).apply { addView(content) })
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
                    if (result.startsWith("THREAT MATCH:")) threats++
                    results.add(name + ": " + result)
                    temp.delete()
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
            }
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
