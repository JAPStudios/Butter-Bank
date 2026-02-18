package com.example.butterbank

import android.os.Bundle
import android.widget.Button
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import java.text.NumberFormat

class MainActivity : AppCompatActivity() {
    private val moneyFormat = NumberFormat.getCurrencyInstance()

    private val ledger = BankLedger(
        hybridAccount = Account(
            accountNumber = "•••• 2401",
            accountType = "Hybrid Account",
            balance = 1250.00
        ),
        creditLimit = 500.00
    )

    private lateinit var accountBalanceText: TextView
    private lateinit var creditStatusText: TextView
    private lateinit var statusText: TextView
    private lateinit var transactionHistoryText: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        accountBalanceText = findViewById(R.id.accountBalanceText)
        creditStatusText = findViewById(R.id.creditStatusText)
        statusText = findViewById(R.id.statusText)
        transactionHistoryText = findViewById(R.id.transactionHistoryText)

        val addFundsButton: Button = findViewById(R.id.addFundsButton)
        val spendButton: Button = findViewById(R.id.spendButton)
        val repayCreditButton: Button = findViewById(R.id.repayCreditButton)

        addFundsButton.setOnClickListener {
            val success = ledger.addFunds(100.00)
            statusText.text = if (success) {
                getString(R.string.add_funds_success, moneyFormat.format(100.00))
            } else {
                getString(R.string.operation_failed)
            }
            refreshUi()
        }

        spendButton.setOnClickListener {
            val success = ledger.spend(50.00)
            statusText.text = if (success) {
                getString(R.string.spend_success, moneyFormat.format(50.00))
            } else {
                getString(R.string.spend_failed)
            }
            refreshUi()
        }

        repayCreditButton.setOnClickListener {
            val success = ledger.repayCreditFromCash(25.00)
            statusText.text = if (success) {
                getString(R.string.repay_credit_success, moneyFormat.format(25.00))
            } else {
                getString(R.string.repay_credit_failed)
            }
            refreshUi()
        }

        refreshUi()
    }

    private fun refreshUi() {
        val account = ledger.getAccount()

        accountBalanceText.text = getString(
            R.string.account_line,
            account.accountType,
            account.accountNumber,
            moneyFormat.format(account.balance)
        )

        creditStatusText.text = getString(
            R.string.credit_line,
            moneyFormat.format(ledger.getCreditUsed()),
            moneyFormat.format(ledger.availableCredit()),
            moneyFormat.format(ledger.getCreditLimit())
        )

        val historyText = ledger.getHistory()
            .take(8)
            .joinToString(separator = "\n") { tx ->
                "${tx.timestamp} • ${tx.description}: ${moneyFormat.format(tx.amount)}"
            }

        transactionHistoryText.text = if (historyText.isNotBlank()) {
            historyText
        } else {
            getString(R.string.no_transactions)
        }
    }
}
