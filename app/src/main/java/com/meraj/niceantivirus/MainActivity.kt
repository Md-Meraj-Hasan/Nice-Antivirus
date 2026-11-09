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
    private val worker = Executors.newSingleThreadExecutor()
    private val pickFileRequest = 4101
    private val pickFolderRequest = 4102

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        if (!Python.isStarted()) Python.start(AndroidPlatform(this))
        val content = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(32, 40, 32, 32)
            setBackgroundColor(Color.rgb(16, 24, 32))
        }
        content.addView(TextView(this).apply {
            text = "NICE ANTIVIRUS"
            textSize = 27f
            gravity = Gravity.CENTER
            setTextColor(Color.WHITE)
        }, matchWrap())
        content.addView(TextView(this).apply {
            text = "MOBILE SECURITY • FILE ANALYSIS"
            textSize = 12f
            gravity = Gravity.CENTER
            setTextColor(Color.rgb(40, 199, 111))
            setPadding(0, 12, 0, 28)
        }, matchWrap())
        status = TextView(this).apply {
            text = "Protection engine ready. Choose a file or folder to scan."
            textSize = 15f
            setTextColor(Color.WHITE)
            setPadding(0, 20, 0, 24)
        }
        content.addView(status, matchWrap())
        addButton(content, "SCAN A FILE / APK") { chooseFile() }
        addButton(content, "SCAN A FOLDER / SD CARD") { chooseFolder() }
        addButton(content, "RUN ENGINE SELF-CHECK") { runSelfCheck() }
        addButton(content, "SIGNATURE DATABASE UPDATE") {
            status.text = "Online updater framework is present. Production updates remain locked until the trusted publisher signing key and official HTTPS manifest endpoint are configured."
        }
        setContentView(ScrollView(this).apply { addView(content) })
    }

    private fun addButton(parent: LinearLayout, label: String, action: () -> Unit) {
        parent.addView(Button(this).apply {
            text = label
            isAllCaps = false
            setOnClickListener { action() }
        }, matchWrap().apply { bottomMargin = 12 })
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
        status.text = "Reading selected folder…"
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
        runOnUiThread { status.text = "Scanning " + uris.size + " selected item(s)…" }
        worker.execute {
            val results = mutableListOf<String>()
            val python = Python.getInstance().getModule("antivirus.scanner")
            val cache = File(cacheDir, "scan")
            cache.mkdirs()
            uris.forEach { uri ->
                try {
                    val name = queryDisplayName(uri) ?: "selected_file"
                    val safeName = name.replace(Regex("[^A-Za-z0-9._-]"), "_").take(100)
                    val temp = File.createTempFile("scan_", "_" + safeName, cache)
                    contentResolver.openInputStream(uri)?.use { input ->
                        temp.outputStream().use { output -> input.copyTo(output) }
                    } ?: throw IllegalStateException("Cannot open selected document")
                    val result = python.callAttr("scan_local_file", temp.absolutePath, File(filesDir, "signatures.db").absolutePath).toString()
                    results.add(name + ": " + result)
                    temp.delete()
                } catch (error: Exception) {
                    results.add(uri.toString() + ": ERROR - " + (error.localizedMessage ?: "unreadable"))
                }
            }
            val summary = results.take(30).joinToString("\n")
            runOnUiThread {
                status.text = "Scan complete: " + results.size + " item(s) checked.\n\n" + summary +
                    if (results.size > 30) "\n…and " + (results.size - 30) + " more." else ""
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
