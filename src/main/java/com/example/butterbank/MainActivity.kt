package com.example.butterbank

import android.app.Activity
import android.app.AlertDialog
import android.content.Intent
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.net.Uri
import android.text.InputType
import android.view.Gravity
import android.view.View
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import org.json.JSONArray
import org.json.JSONObject
import java.text.DateFormat
import java.util.Calendar
import java.util.Date
import java.util.UUID
import java.util.Locale
import java.io.ByteArrayOutputStream
import java.io.IOException
import java.net.HttpURLConnection
import java.net.URL
import java.nio.charset.StandardCharsets
import java.util.concurrent.Executors

/**
 * Offline-first Butter Bank prototype.
 *
 * This screen combines a local personal-finance ledger, an encrypted local
 * Ed25519 wallet, and a read-only public Milkchain account viewer. It does not
 * hold deposits, issue credit, or connect to external payment rails.
 */
class MainActivity : Activity() {
    private val ledgerStore by lazy { LedgerStore(this) }
    private val walletStore by lazy { WalletStore(this) }
    private val settings by lazy { getSharedPreferences("butter_bank_settings", MODE_PRIVATE) }
    private val networkExecutor = Executors.newSingleThreadExecutor()
    private var storageUnavailable = false
    private val entries = mutableListOf<LedgerEntry>()

    private lateinit var balanceValue: TextView
    private lateinit var incomeValue: TextView
    private lateinit var expenseValue: TextView
    private lateinit var budgetValue: TextView
    private lateinit var historyContainer: LinearLayout
    private lateinit var titleInput: EditText
    private lateinit var amountInput: EditText
    private lateinit var categoryInput: EditText
    private lateinit var typeSpinner: Spinner
    private lateinit var budgetInput: EditText
    private lateinit var nodeUrlInput: EditText
    private lateinit var accountAddressInput: EditText
    private lateinit var accountLoadButton: Button
    private lateinit var accountBalanceValue: TextView
    private lateinit var accountHistoryContainer: LinearLayout
    private lateinit var walletStatusValue: TextView
    private var pendingWalletBackup: String? = null

    private var monthlyBudgetCents: Long? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        loadLocalData()
        setContentView(buildScreen())
        renderDashboard()
        if (storageUnavailable) {
            AlertDialog.Builder(this)
                .setTitle("Ledger storage unavailable")
                .setMessage("The encrypted ledger could not be unlocked. Existing stored data has been preserved. No changes can be saved until storage is available again.")
                .setPositiveButton("OK", null)
                .show()
        }
    }

    private fun buildScreen(): View {
        val scroll = ScrollView(this).apply {
            isFillViewport = true
            setBackgroundColor(0xFFF3F5F0.toInt())
        }
        val page = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(24), dp(20), dp(32))
        }
        scroll.addView(page)
        val originalLeft = dp(20)
        val originalTop = dp(24)
        val originalRight = dp(20)
        val originalBottom = dp(32)
        ViewCompat.setOnApplyWindowInsetsListener(scroll) { _, insets ->
            val systemBars = insets.getInsets(
                WindowInsetsCompat.Type.systemBars() or WindowInsetsCompat.Type.displayCutout()
            )
            page.setPadding(
                originalLeft + systemBars.left,
                originalTop + systemBars.top,
                originalRight + systemBars.right,
                originalBottom + systemBars.bottom
            )
            insets
        }
        ViewCompat.requestApplyInsets(scroll)

        page.addView(label("BUTTER BANK", 28, 0xFF244B35.toInt(), true))
        page.addView(label("Your money, organized.", 17, 0xFF26352B.toInt(), true).apply {
            setPadding(0, dp(5), 0, dp(14))
        })
        page.addView(card().apply {
            addView(label("LOCAL PROTOTYPE · NO BANKING CONNECTION", 12, 0xFF77520A.toInt(), true))
            addView(label(
                "Records entered here are saved on this device. This prototype does not open bank accounts, hold deposits, issue credit, or process payments.",
                14,
                0xFF514B3D.toInt()
            ).apply { setPadding(0, dp(7), 0, 0) })
        })

        page.addView(sectionHeading("Overview"))
        page.addView(card().apply {
            addView(label("Recorded balance", 13, 0xFF5B685F.toInt()))
            balanceValue = label("$0.00", 30, 0xFF244B35.toInt(), true)
            addView(balanceValue)
            val totals = LinearLayout(context).apply {
                orientation = LinearLayout.HORIZONTAL
                weightSum = 2f
                setPadding(0, dp(15), 0, 0)
            }
            val incomeColumn = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
            incomeColumn.addView(label("Income recorded", 12, 0xFF5B685F.toInt()))
            incomeValue = label("$0.00", 17, 0xFF244B35.toInt(), true)
            incomeColumn.addView(incomeValue)
            val expenseColumn = LinearLayout(context).apply { orientation = LinearLayout.VERTICAL }
            expenseColumn.addView(label("Expenses recorded", 12, 0xFF5B685F.toInt()))
            expenseValue = label("$0.00", 17, 0xFF8B3D32.toInt(), true)
            expenseColumn.addView(expenseValue)
            totals.addView(incomeColumn, LinearLayout.LayoutParams(0, -2, 1f))
            totals.addView(expenseColumn, LinearLayout.LayoutParams(0, -2, 1f))
            addView(totals)
        })

        page.addView(sectionHeading("Monthly spending limit"))
        page.addView(card().apply {
            budgetValue = label("No monthly limit set", 14, 0xFF26352B.toInt(), true)
            addView(budgetValue)
            budgetInput = field("Enter a monthly limit (for example, 850.00)", decimal = true)
            addView(budgetInput)
            addView(actionButton("Save monthly limit") {
                val parsed = Money.parsePositiveCents(budgetInput.text.toString())
                if (parsed == null) {
                    toast("Enter a positive amount with no more than two decimal places.")
                } else {
                    val previousBudget = monthlyBudgetCents
                    monthlyBudgetCents = parsed
                    if (saveLocalData()) {
                        budgetInput.text.clear()
                        renderDashboard()
                        toast("Monthly limit saved securely on this device.")
                    } else {
                        monthlyBudgetCents = previousBudget
                    }
                }
            })
        })

        page.addView(sectionHeading("Milkchain account"))
        page.addView(card().apply {
            addView(label(
                "Read a public Biscuits account from a remote Milkchain node. Remote connections require HTTPS.",
                13,
                0xFF5B685F.toInt()
            ).apply { setPadding(0, 0, 0, dp(10)) })
            walletStatusValue = label(
                walletStore.publicAddress()?.let { "On-device wallet: $it" } ?: "No on-device wallet",
                13,
                0xFF244B35.toInt(),
                true
            ).apply { setPadding(0, 0, 0, dp(8)) }
            addView(walletStatusValue)
            addView(actionButton("Create on-device wallet") { createDeviceWallet() })
            addView(actionButton("Import encrypted wallet backup") { chooseWalletBackupToImport() })
            addView(actionButton("Export encrypted wallet backup") { exportWalletBackup() })
            nodeUrlInput = field("HTTPS Milkchain node URL")
            nodeUrlInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_URI
            nodeUrlInput.setText(settings.getString(KEY_NODE_URL, ""))
            addView(nodeUrlInput)
            accountAddressInput = field("Biscuits public address (64 hexadecimal characters)")
            accountAddressInput.inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD
            accountAddressInput.setText(settings.getString(KEY_ACCOUNT_ADDRESS, walletStore.publicAddress() ?: ""))
            addView(accountAddressInput)
            accountLoadButton = actionButton("Load Milkchain account") { loadMilkchainAccount() }
            addView(accountLoadButton)
            accountBalanceValue = label("Account not loaded", 18, 0xFF244B35.toInt(), true).apply {
                setPadding(0, dp(12), 0, dp(8))
            }
            addView(accountBalanceValue)
            accountHistoryContainer = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
            }
            addView(accountHistoryContainer)
        })

        page.addView(sectionHeading("Add a record"))
        page.addView(card().apply {
            titleInput = field("Description")
            addView(titleInput)
            amountInput = field("Amount (for example, 24.99)", decimal = true)
            addView(amountInput)
            categoryInput = field("Category (for example, groceries or wages)")
            addView(categoryInput)
            typeSpinner = Spinner(context).apply {
                adapter = ArrayAdapter(
                    context,
                    android.R.layout.simple_spinner_dropdown_item,
                    listOf("Expense", "Income")
                )
            }
            addView(typeSpinner, LinearLayout.LayoutParams(-1, dp(48)))
            addView(actionButton("Save record") { addEntry() })
        })

        page.addView(sectionHeading("Transaction history"))
        page.addView(card().apply {
            historyContainer = LinearLayout(context).apply {
                orientation = LinearLayout.VERTICAL
            }
            addView(historyContainer)
        })

        page.addView(label(
            "Prototype limitation: these are manually entered personal records, not verified bank transactions or available funds. Records are encrypted at rest with an Android Keystore key and remain on this device.",
            12,
            0xFF5B685F.toInt()
        ).apply { setPadding(dp(3), dp(16), dp(3), 0) })

        return scroll
    }

    private fun addEntry() {
        val description = titleInput.text.toString().trim()
        val amount = Money.parsePositiveCents(amountInput.text.toString())
        val category = categoryInput.text.toString().trim().ifEmpty { "Uncategorized" }

        if (description.isEmpty()) {
            toast("Enter a description.")
            return
        }
        if (amount == null) {
            toast("Enter a positive amount with no more than two decimal places.")
            return
        }

        val type = if (typeSpinner.selectedItemPosition == 1) EntryType.INCOME else EntryType.EXPENSE
        val newEntry = LedgerEntry(
            id = UUID.randomUUID().toString(),
            description = description,
            amountCents = amount,
            type = type,
            category = category,
            timestampMillis = System.currentTimeMillis()
        )
        val candidateEntries = entries.toMutableList().apply { add(0, newEntry) }
        try {
            // Validate every dashboard aggregate before persisting the new record.
            LedgerMath.totalCents(candidateEntries, EntryType.INCOME)
            LedgerMath.totalCents(candidateEntries, EntryType.EXPENSE)
            LedgerMath.balanceCents(candidateEntries)
        } catch (_: ArithmeticException) {
            toast("This record would exceed the supported ledger total.")
            return
        }
        entries.add(0, newEntry)
        if (!saveLocalData()) {
            entries.removeAll { it.id == newEntry.id }
            return
        }
        titleInput.text.clear()
        amountInput.text.clear()
        categoryInput.text.clear()
        renderDashboard()
        toast("Record saved on this device.")
    }

    private fun renderDashboard() {
        if (storageUnavailable) {
            balanceValue.text = "Unavailable"
            incomeValue.text = "Unavailable"
            expenseValue.text = "Unavailable"
            budgetValue.text = "Unavailable"
            historyContainer.removeAllViews()
            historyContainer.addView(label(
                "Encrypted records could not be unlocked. Stored data has been preserved; no balances are shown.",
                14,
                0xFF8B3D32.toInt(),
                true
            ))
            return
        }
        val income = LedgerMath.totalCents(entries, EntryType.INCOME)
        val expenses = LedgerMath.totalCents(entries, EntryType.EXPENSE)
        val balance = LedgerMath.balanceCents(entries)

        balanceValue.text = Money.formatCents(balance)
        incomeValue.text = Money.formatCents(income)
        expenseValue.text = Money.formatCents(expenses)

        val budget = monthlyBudgetCents
        if (budget == null) {
            budgetValue.text = "No monthly limit set"
        } else {
            val monthExpenses = currentMonthExpenses()
            val remaining = budget - monthExpenses
            budgetValue.text = "This month: ${Money.formatCents(monthExpenses)} of ${Money.formatCents(budget)}\n" +
                if (remaining >= 0) "${Money.formatCents(remaining)} remaining"
                else "${Money.formatCents(-remaining)} over the limit"
        }

        historyContainer.removeAllViews()
        if (entries.isEmpty()) {
            historyContainer.addView(label("No records yet. Add an income or expense above.", 14, 0xFF5B685F.toInt()))
            return
        }

        entries.forEach { entry ->
            val row = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setPadding(0, dp(10), 0, dp(10))
            }
            val top = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
            }
            val details = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
            }
            details.addView(label(entry.description, 15, 0xFF26352B.toInt(), true))
            val date = DateFormat.getDateTimeInstance(DateFormat.MEDIUM, DateFormat.SHORT)
                .format(Date(entry.timestampMillis))
            details.addView(label("${entry.category} · $date", 12, 0xFF68736B.toInt()))
            val amountColor = if (entry.type == EntryType.INCOME) 0xFF244B35.toInt() else 0xFF8B3D32.toInt()
            val signedAmount = (if (entry.type == EntryType.INCOME) "+" else "−") + Money.formatCents(entry.amountCents)
            top.addView(details, LinearLayout.LayoutParams(0, -2, 1f))
            top.addView(label(signedAmount, 14, amountColor, true))
            row.addView(top)
            row.setOnLongClickListener {
                AlertDialog.Builder(this)
                    .setTitle("Delete this record?")
                    .setMessage("This removes the manually entered record from this device.")
                    .setNegativeButton("Cancel", null)
                    .setPositiveButton("Delete") { _, _ ->
                        val originalIndex = entries.indexOfFirst { it.id == entry.id }
                        entries.removeAll { it.id == entry.id }
                        if (saveLocalData()) renderDashboard()
                        else if (originalIndex >= 0) entries.add(originalIndex.coerceAtMost(entries.size), entry)
                    }
                    .show()
                true
            }
            historyContainer.addView(row)
            val divider = View(this).apply { setBackgroundColor(0xFFE2E7E0.toInt()) }
            historyContainer.addView(divider, LinearLayout.LayoutParams(-1, dp(1)))
        }
    }

    private fun currentMonthExpenses(): Long {
        val now = Calendar.getInstance()
        val year = now.get(Calendar.YEAR)
        val month = now.get(Calendar.MONTH)
        return entries.filter { entry ->
            if (entry.type != EntryType.EXPENSE) return@filter false
            val date = Calendar.getInstance().apply { timeInMillis = entry.timestampMillis }
            date.get(Calendar.YEAR) == year && date.get(Calendar.MONTH) == month
        }.fold(0L) { total, entry -> Math.addExact(total, entry.amountCents) }
    }

    private fun loadLocalData() {
        try {
            val snapshot = ledgerStore.load()
            monthlyBudgetCents = snapshot.monthlyBudgetCents
            val array = JSONArray(snapshot.entriesJson)
            for (index in 0 until array.length()) {
                val item = array.getJSONObject(index)
                val type = EntryType.valueOf(item.getString("type"))
                val amount = item.getLong("amountCents")
                if (amount <= 0L) throw IllegalArgumentException("Invalid stored amount.")
                entries.add(LedgerEntry(
                    id = item.getString("id"),
                    description = item.getString("description"),
                    amountCents = amount,
                    type = type,
                    category = item.optString("category", "Uncategorized"),
                    timestampMillis = item.getLong("timestampMillis")
                ))
            }
            LedgerMath.totalCents(entries, EntryType.INCOME)
            LedgerMath.totalCents(entries, EntryType.EXPENSE)
            LedgerMath.balanceCents(entries)
        } catch (_: Exception) {
            entries.clear()
            monthlyBudgetCents = null
            storageUnavailable = true
        }
    }

    private fun saveLocalData(): Boolean {
        if (storageUnavailable) {
            toast("Ledger storage is unavailable. Existing data was preserved.")
            return false
        }
        val array = JSONArray()
        entries.forEach { entry ->
            array.put(JSONObject().apply {
                put("id", entry.id)
                put("description", entry.description)
                put("amountCents", entry.amountCents)
                put("type", entry.type.name)
                put("category", entry.category)
                put("timestampMillis", entry.timestampMillis)
            })
        }
        return try {
            ledgerStore.save(LedgerStore.Snapshot(array.toString(), monthlyBudgetCents))
            true
        } catch (_: Exception) {
            toast("Could not securely save the ledger. The previous saved copy remains intact.")
            false
        }
    }

    private fun createDeviceWallet() {
        if (walletStore.hasWallet()) {
            toast("A wallet already exists on this device.")
            return
        }
        try {
            val public = walletStore.createWallet()
            walletStatusValue.text = "On-device wallet: $public"
            accountAddressInput.setText(public)
            toast("Wallet created. Save an encrypted backup before changing devices or reinstalling.")
            requestNewWalletBackupPassphrase { passphrase ->
                saveWalletBackup(passphrase)
            }
        } catch (error: Exception) {
            toast(error.message ?: "Could not create the wallet.")
        }
    }

    private fun exportWalletBackup() {
        if (!walletStore.hasWallet()) {
            toast("Create or import a wallet first.")
            return
        }
        requestNewWalletBackupPassphrase { passphrase ->
            saveWalletBackup(passphrase)
        }
    }

    private fun saveWalletBackup(passphrase: String) {
        try {
            pendingWalletBackup = walletStore.exportBackup(passphrase)
            val intent = Intent(Intent.ACTION_CREATE_DOCUMENT).apply {
                addCategory(Intent.CATEGORY_OPENABLE)
                type = "application/json"
                putExtra(Intent.EXTRA_TITLE, "biscuits-wallet-backup.json")
            }
            startActivityForResult(intent, REQUEST_EXPORT_WALLET_BACKUP)
        } catch (error: Exception) {
            pendingWalletBackup = null
            toast(error.message ?: "Could not create the encrypted wallet backup.")
        }
    }

    private fun chooseWalletBackupToImport() {
        if (walletStore.hasWallet()) {
            toast("A wallet already exists on this device. Export it before replacing device data.")
            return
        }
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "application/json"
        }
        startActivityForResult(intent, REQUEST_IMPORT_WALLET_BACKUP)
    }

    private fun requestWalletPassphrase(onSubmit: (String) -> Unit) {
        val input = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Wallet backup passphrase"
        }
        val dialog = AlertDialog.Builder(this)
            .setTitle("Unlock encrypted wallet backup")
            .setView(input)
            .setNegativeButton("Cancel", null)
            .setPositiveButton("Import", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val passphrase = input.text.toString()
                if (passphrase.length < 12) {
                    input.error = "Passphrase must contain at least 12 characters"
                    return@setOnClickListener
                }
                dialog.dismiss()
                onSubmit(passphrase)
            }
        }
        dialog.show()
    }

    private fun requestNewWalletBackupPassphrase(onSubmit: (String) -> Unit) {
        val fields = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(dp(20), dp(8), dp(20), 0)
        }
        val first = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "New backup passphrase (12+ characters)"
        }
        val second = EditText(this).apply {
            inputType = InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_VARIATION_PASSWORD
            hint = "Confirm backup passphrase"
        }
        fields.addView(first)
        fields.addView(second)
        val dialog = AlertDialog.Builder(this)
            .setTitle("Protect wallet backup")
            .setMessage("The passphrase is not stored. It is required to restore this wallet from the backup file.")
            .setView(fields)
            .setNegativeButton("Later", null)
            .setPositiveButton("Save backup", null)
            .create()
        dialog.setOnShowListener {
            dialog.getButton(AlertDialog.BUTTON_POSITIVE).setOnClickListener {
                val passphrase = first.text.toString()
                if (passphrase.length < 12) {
                    first.error = "Passphrase must contain at least 12 characters"
                    return@setOnClickListener
                }
                if (passphrase != second.text.toString()) {
                    second.error = "Passphrases do not match"
                    return@setOnClickListener
                }
                dialog.dismiss()
                onSubmit(passphrase)
            }
        }
        dialog.show()
    }

    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (resultCode != RESULT_OK || data?.data == null) {
            if (requestCode == REQUEST_EXPORT_WALLET_BACKUP) {
                pendingWalletBackup = null
                toast("Wallet remains stored on this device; export a backup before changing devices.")
            }
            return
        }
        val uri = data.data ?: return
        when (requestCode) {
            REQUEST_EXPORT_WALLET_BACKUP -> {
                val backup = pendingWalletBackup ?: return
                try {
                    contentResolver.openOutputStream(uri)?.use {
                        it.write(backup.toByteArray(StandardCharsets.UTF_8))
                    } ?: throw IOException("Could not open the selected backup destination.")
                    pendingWalletBackup = null
                    toast("Encrypted wallet backup saved.")
                } catch (error: Exception) {
                    pendingWalletBackup = null
                    toast(error.message ?: "Could not save the wallet backup.")
                }
            }
            REQUEST_IMPORT_WALLET_BACKUP -> {
                try {
                    val backup = readWalletBackup(uri)
                    requestWalletPassphrase { passphrase ->
                        try {
                            val public = walletStore.importBackup(backup, passphrase)
                            walletStatusValue.text = "On-device wallet: $public"
                            accountAddressInput.setText(public)
                            toast("Encrypted wallet imported.")
                        } catch (error: Exception) {
                            toast(error.message ?: "Could not import the encrypted wallet.")
                        }
                    }
                } catch (error: Exception) {
                    toast(error.message ?: "Could not read the selected wallet backup.")
                }
            }
        }
    }

    private fun readWalletBackup(uri: Uri): String {
        val output = ByteArrayOutputStream()
        contentResolver.openInputStream(uri)?.use { input ->
            val buffer = ByteArray(8_192)
            var total = 0
            while (true) {
                val count = input.read(buffer)
                if (count < 0) break
                total += count
                if (total > MAX_NODE_RESPONSE_BYTES) throw IOException("Wallet backup exceeds the 1 MB limit.")
                output.write(buffer, 0, count)
            }
        } ?: throw IOException("Could not open the selected wallet backup.")
        return String(output.toByteArray(), StandardCharsets.UTF_8)
    }

    private fun loadMilkchainAccount() {
        val nodeUrl = try {
            validateNodeUrl(nodeUrlInput.text.toString().trim())
        } catch (error: IllegalArgumentException) {
            toast(error.message ?: "Enter a valid HTTPS node URL.")
            return
        }
        val address = accountAddressInput.text.toString().trim()
        if (!address.matches(Regex("^[0-9a-fA-F]{64}$"))) {
            toast("Enter a 32-byte hexadecimal Biscuits public address.")
            return
        }
        val normalizedAddress = address.lowercase(Locale.ROOT)
        settings.edit()
            .putString(KEY_NODE_URL, nodeUrl)
            .putString(KEY_ACCOUNT_ADDRESS, normalizedAddress)
            .apply()
        accountLoadButton.isEnabled = false
        accountBalanceValue.text = "Loading account…"
        accountHistoryContainer.removeAllViews()

        networkExecutor.execute {
            try {
                val balance = fetchJson("$nodeUrl/balance?address=$normalizedAddress")
                val history = fetchJson("$nodeUrl/history?address=$normalizedAddress&limit=20")
                val decimals = balance.getInt("decimals")
                if (decimals !in 0..18 || balance.getString("address") != normalizedAddress) {
                    throw IOException("The node returned invalid account metadata.")
                }
                val amount = TokenAmount.formatAtomicUnits(balance.get("balance").toString(), decimals)
                val symbol = balance.optString("symbol", "Biscuits")
                val total = history.getInt("total")
                val events = history.getJSONArray("history")
                val rows = mutableListOf<String>()
                for (index in 0 until events.length()) {
                    val event = events.getJSONObject(index)
                    val eventAmount = TokenAmount.formatAtomicUnits(event.get("amount").toString(), decimals)
                    val direction = event.optString("direction", event.optString("type", "activity"))
                    val block = event.optLong("block_height", -1L)
                    val fee = if (event.has("fee")) {
                        " · fee ${TokenAmount.formatAtomicUnits(event.get("fee").toString(), decimals)} $symbol"
                    } else ""
                    rows.add("$direction  $eventAmount $symbol · block $block$fee")
                }
                runOnUiThread {
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    accountLoadButton.isEnabled = true
                    accountBalanceValue.text = "$amount $symbol"
                    accountHistoryContainer.removeAllViews()
                    accountHistoryContainer.addView(label(
                        "Recent activity ($total total records; showing ${rows.size})",
                        13,
                        0xFF5B685F.toInt(),
                        true
                    ).apply { setPadding(0, dp(8), 0, dp(6)) })
                    if (rows.isEmpty()) {
                        accountHistoryContainer.addView(label("No account activity returned.", 13, 0xFF5B685F.toInt()))
                    } else {
                        rows.forEach { row ->
                            accountHistoryContainer.addView(label(row, 13, 0xFF26352B.toInt()).apply {
                                setPadding(0, dp(6), 0, dp(6))
                            })
                        }
                    }
                }
            } catch (error: Exception) {
                runOnUiThread {
                    if (isFinishing || isDestroyed) return@runOnUiThread
                    accountLoadButton.isEnabled = true
                    accountBalanceValue.text = "Account unavailable"
                    accountHistoryContainer.removeAllViews()
                    toast(error.message ?: "Could not load the Milkchain account.")
                }
            }
        }
    }

    private fun validateNodeUrl(raw: String): String {
        val uri = Uri.parse(raw)
        if (uri.scheme != "https" || uri.host.isNullOrBlank()
            || uri.encodedAuthority?.contains('@') == true
            || uri.encodedPath !in listOf("", "/")
            || uri.encodedQuery != null || uri.encodedFragment != null
            || uri.port == 0 || uri.port > 65535
        ) {
            throw IllegalArgumentException("Remote Milkchain nodes must use a base HTTPS URL without credentials or a path.")
        }
        return raw.trimEnd('/')
    }

    private fun fetchJson(address: String): JSONObject {
        val connection = URL(address).openConnection() as HttpURLConnection
        connection.requestMethod = "GET"
        connection.instanceFollowRedirects = false
        connection.connectTimeout = 8_000
        connection.readTimeout = 8_000
        connection.setRequestProperty("Accept", "application/json")
        try {
            val status = connection.responseCode
            if (status !in 200..299) throw IOException("Milkchain node returned HTTP $status.")
            val output = ByteArrayOutputStream()
            connection.inputStream.use { input ->
                val buffer = ByteArray(8_192)
                var total = 0
                while (true) {
                    val count = input.read(buffer)
                    if (count < 0) break
                    total += count
                    if (total > MAX_NODE_RESPONSE_BYTES) {
                        throw IOException("Milkchain response exceeds the 1 MB limit.")
                    }
                    output.write(buffer, 0, count)
                }
            }
            return JSONObject(String(output.toByteArray(), StandardCharsets.UTF_8))
        } finally {
            connection.disconnect()
        }
    }

    override fun onDestroy() {
        networkExecutor.shutdownNow()
        super.onDestroy()
    }

    private fun sectionHeading(text: String) =
        label(text, 19, 0xFF26352B.toInt(), true).apply {
            setPadding(dp(2), dp(22), dp(2), dp(10))
        }

    private fun card() = LinearLayout(this).apply {
        orientation = LinearLayout.VERTICAL
        setPadding(dp(17), dp(16), dp(17), dp(16))
        background = GradientDrawable().apply {
            setColor(0xFFFFFFFF.toInt())
            cornerRadius = dp(14).toFloat()
            setStroke(dp(1), 0xFFE0E6DE.toInt())
        }
    }

    private fun label(text: String, size: Int, color: Int, bold: Boolean = false) =
        TextView(this).apply {
            this.text = text
            textSize = size.toFloat()
            setTextColor(color)
            if (bold) setTypeface(typeface, Typeface.BOLD)
        }

    private fun field(hintText: String, decimal: Boolean = false) =
        EditText(this).apply {
            hint = hintText
            textSize = 15f
            isSingleLine = true
            inputType = if (decimal) {
                InputType.TYPE_CLASS_NUMBER or InputType.TYPE_NUMBER_FLAG_DECIMAL
            } else {
                InputType.TYPE_CLASS_TEXT or InputType.TYPE_TEXT_FLAG_CAP_SENTENCES
            }
            setPadding(dp(12), dp(8), dp(12), dp(8))
            background = GradientDrawable().apply {
                setColor(0xFFF8FAF6.toInt())
                cornerRadius = dp(9).toFloat()
                setStroke(dp(1), 0xFFDDE4DA.toInt())
            }
            layoutParams = LinearLayout.LayoutParams(-1, dp(50)).apply {
                bottomMargin = dp(10)
            }
        }

    private fun actionButton(text: String, action: () -> Unit) =
        Button(this).apply {
            this.text = text
            isAllCaps = false
            setOnClickListener { action() }
            layoutParams = LinearLayout.LayoutParams(-1, dp(50)).apply {
                topMargin = dp(6)
            }
        }

    private fun toast(message: String) =
        Toast.makeText(this, message, Toast.LENGTH_SHORT).show()

    private fun dp(value: Int): Int = (value * resources.displayMetrics.density).toInt()

    companion object {
        private const val REQUEST_EXPORT_WALLET_BACKUP = 4101
        private const val REQUEST_IMPORT_WALLET_BACKUP = 4102
        private const val KEY_NODE_URL = "milkchain_node_url"
        private const val KEY_ACCOUNT_ADDRESS = "milkchain_account_address"
        private const val MAX_NODE_RESPONSE_BYTES = 1_000_000
    }
}
