package com.example.butterbank

import android.app.Activity
import android.app.AlertDialog
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.os.Bundle
import android.text.InputType
import android.view.Gravity
import android.view.View
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

/**
 * Offline-first Butter Bank prototype.
 *
 * This screen is a local personal-finance ledger only. It does not create a
 * bank account, hold deposits, issue credit, connect to payment rails, or
 * represent a balance held by a financial institution.
 */
class MainActivity : Activity() {
    private val preferences by lazy { getSharedPreferences("butter_bank_local", MODE_PRIVATE) }
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

    private var monthlyBudgetCents: Long? = null

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        loadLocalData()
        setContentView(buildScreen())
        renderDashboard()
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
                    monthlyBudgetCents = parsed
                    preferences.edit().putLong(KEY_BUDGET, parsed).apply()
                    budgetInput.text.clear()
                    renderDashboard()
                    toast("Monthly limit saved on this device.")
                }
            })
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
            "Prototype limitation: these are manually entered personal records, not verified bank transactions or available funds. Data remains in this app's local storage and is not encrypted by this prototype.",
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
        entries.add(
            0,
            LedgerEntry(
                id = UUID.randomUUID().toString(),
                description = description,
                amountCents = amount,
                type = type,
                category = category,
                timestampMillis = System.currentTimeMillis()
            )
        )
        saveLocalData()
        titleInput.text.clear()
        amountInput.text.clear()
        categoryInput.text.clear()
        renderDashboard()
        toast("Record saved on this device.")
    }

    private fun renderDashboard() {
        val income = entries.filter { it.type == EntryType.INCOME }.sumOf { it.amountCents }
        val expenses = entries.filter { it.type == EntryType.EXPENSE }.sumOf { it.amountCents }
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
                        entries.removeAll { it.id == entry.id }
                        saveLocalData()
                        renderDashboard()
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
        }.sumOf { it.amountCents }
    }

    private fun loadLocalData() {
        monthlyBudgetCents = if (preferences.contains(KEY_BUDGET)) {
            preferences.getLong(KEY_BUDGET, 0L).takeIf { it > 0L }
        } else null

        val stored = preferences.getString(KEY_ENTRIES, "[]") ?: "[]"
        try {
            val array = JSONArray(stored)
            for (index in 0 until array.length()) {
                val item = array.getJSONObject(index)
                val type = EntryType.valueOf(item.getString("type"))
                val amount = item.getLong("amountCents")
                if (amount <= 0L) continue
                entries.add(
                    LedgerEntry(
                        id = item.getString("id"),
                        description = item.getString("description"),
                        amountCents = amount,
                        type = type,
                        category = item.optString("category", "Uncategorized"),
                        timestampMillis = item.getLong("timestampMillis")
                    )
                )
            }
        } catch (_: Exception) {
            entries.clear()
            preferences.edit().remove(KEY_ENTRIES).apply()
        }
    }

    private fun saveLocalData() {
        val array = JSONArray()
        entries.forEach { entry ->
            array.put(
                JSONObject().apply {
                    put("id", entry.id)
                    put("description", entry.description)
                    put("amountCents", entry.amountCents)
                    put("type", entry.type.name)
                    put("category", entry.category)
                    put("timestampMillis", entry.timestampMillis)
                }
            )
        }
        preferences.edit().putString(KEY_ENTRIES, array.toString()).apply()
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
        private const val KEY_ENTRIES = "ledger_entries"
        private const val KEY_BUDGET = "monthly_budget_cents"
    }
}
