package io.github.iml1s.crypto.demo.app

import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.semantics.testTag



import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.zIndex
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.*
import androidx.compose.ui.unit.sp
import androidx.compose.foundation.layout.PaddingValues

import io.github.iml1s.wallet.UnifiedWallet
import io.github.iml1s.wallet.NetworkType
import kotlinx.coroutines.launch
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

data class WalletEntry(
    val chain: String,
    val emoji: String,
    val address: String,
    val path: String,
    val color: Color,
    val balance: String = "Loading..."
)

@Composable
fun App(isMock: Boolean = false) {
    val scope = rememberCoroutineScope()
    var mnemonic by remember {
        mutableStateOf("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
    }
    
    // Checksmith Core (Unified Wallet)
    var unifiedWallet by remember { mutableStateOf<UnifiedWallet?>(null) }
    
    // UI State
    var wallets by remember { mutableStateOf(emptyList<WalletEntry>()) }
    var isLoading by remember { mutableStateOf(false) }
    var showSendDialog by remember { mutableStateOf(false) }
    var activeSendChain by remember { mutableStateOf<String?>(null) }
    var networkType by remember { mutableStateOf(NetworkType.MAINNET) }



    MaterialTheme(
        colorScheme = darkColorScheme()
    ) {
        Surface(
            modifier = Modifier.fillMaxSize(),
            color = Color(0xFF0D1117)
        ) {
            Column(
                modifier = Modifier
                    .fillMaxSize()
                    .padding(16.dp)
            ) {
                // Header
                Text(
                    text = "🦄 Unified Wallet Demo",
                    fontSize = 28.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )
                Text(
                    text = "Multi-Chain Wallet with Real-Time Balance",
                    fontSize = 14.sp,
                    color = Color.Gray
                )
                
                Spacer(modifier = Modifier.height(16.dp))

                // Mnemonic Input
                OutlinedTextField(
                    value = mnemonic,
                    onValueChange = { mnemonic = it },
                    label = { Text("BIP39 Mnemonic") },
                    modifier = Modifier.fillMaxWidth(),
                    maxLines = 3,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedTextColor = Color.White,
                        unfocusedTextColor = Color.LightGray,
                        focusedBorderColor = Color(0xFF58A6FF),
                        unfocusedBorderColor = Color.Gray
                    )
                )

                // Network Toggle
                Row(
                    verticalAlignment = Alignment.CenterVertically,
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text("Network:", color = Color.White, fontWeight = FontWeight.Bold)
                    Spacer(modifier = Modifier.width(12.dp))
                    Text(
                        text = "Mainnet",
                        color = if (networkType == NetworkType.MAINNET) Color(0xFF58A6FF) else Color.Gray,
                        fontSize = 14.sp
                    )
                    Switch(
                        modifier = Modifier.semantics { testTag = "networkToggle" },
                        checked = networkType == NetworkType.TESTNET,
                        onCheckedChange = { networkType = if (it) NetworkType.TESTNET else NetworkType.MAINNET },
                        colors = SwitchDefaults.colors(
                            checkedThumbColor = Color(0xFF58A6FF),
                            checkedTrackColor = Color(0xFF58A6FF).copy(alpha = 0.5f),
                            uncheckedThumbColor = Color.Gray,
                            uncheckedTrackColor = Color.DarkGray
                        )
                    )
                    Text(
                        text = "Testnet",
                        color = if (networkType == NetworkType.TESTNET) Color(0xFF58A6FF) else Color.Gray,
                        fontSize = 14.sp
                    )
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Generate Button
                Button(
                    onClick = {
                        isLoading = true
                        scope.launch(Dispatchers.Default) {
                            try {
                                val wallet = UnifiedWallet.create(mnemonic = mnemonic, network = networkType)
                                unifiedWallet = wallet
                                // Initial list with loading balances
                                val initialWallets = listOf(
                                    WalletEntry("Bitcoin", "🟠", wallet.bitcoin.getAddress(), 
                                        if (networkType == NetworkType.TESTNET) "m/84'/1'/0'/0/0" else "m/84'/0'/0'/0/0", 
                                        Color(0xFFF7931A)),
                                    WalletEntry("Ethereum", "🔷", wallet.ethereum.getAddress(), 
                                        "m/44'/60'/0'/0/0", 
                                        Color(0xFF627EEA)),
                                    WalletEntry("Solana", "☀️", wallet.solana.getAddress(), 
                                        "m/44'/501'/0'/0'", 
                                        Color(0xFF00FFA3)),
                                    WalletEntry("Dash", "🔵", wallet.dash.getAddress(), 
                                        if (networkType == NetworkType.TESTNET) "m/44'/1'/0'/0/0" else "m/44'/5'/0'/0/0", 
                                        Color(0xFF008DE4)),
                                    WalletEntry("Zcash", "🟡", wallet.zcash.getAddress(), 
                                        if (networkType == NetworkType.TESTNET) "m/44'/1'/0'/0/0" else "m/44'/133'/0'/0/0", 
                                        Color(0xFFF4B728)),
                                    WalletEntry("Monero", "🟠", wallet.monero.getAddress(), 
                                        "(view-key/seed)", 
                                        Color(0xFFFF6600))
                                )
                                
                                withContext(Dispatchers.Main) {
                                    wallets = initialWallets
                                    isLoading = false
                                }
                                
                                // Launch balance updates
                                initialWallets.forEachIndexed { index, entry ->
                                    launch(Dispatchers.IO) {
                                        try {
                                            val balance = if (isMock) {
                                                "1.23 ${entry.chain.take(3).uppercase()}"
                                            } else {
                                                withTimeout(5000) {
                                                    when(entry.chain) {
                                                        "Bitcoin" -> wallet.bitcoin.getBalance().total + " BTC"
                                                        "Dash" -> wallet.dash.getBalance().total + " DASH"
                                                        "Zcash" -> wallet.zcash.getBalance().total + " ZEC"
                                                        "Ethereum" -> wallet.ethereum.getBalance().total + " ETH"
                                                        "Solana" -> wallet.solana.getBalance().total + " SOL"
                                                        "Monero" -> "Unknown (View-Only)"
                                                        else -> "N/A"
                                                    }
                                                }
                                            }
                                            
                                            withContext(Dispatchers.Main) {
                                                wallets = wallets.toMutableList().apply {
                                                    this[index] = this[index].copy(balance = balance)
                                                }
                                            }
                                        } catch (e: Exception) {
                                            e.printStackTrace()
                                            withContext(Dispatchers.Main) {
                                                wallets = wallets.toMutableList().apply {
                                                    this[index] = this[index].copy(balance = "Error")
                                                }
                                            }
                                        }
                                    }
                                }
                                
                            } catch (e: Exception) {
                                e.printStackTrace()
                                withContext(Dispatchers.Main) {
                                    isLoading = false
                                }
                            }
                        }
                    },
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(
                        containerColor = Color(0xFF238636)
                    ),
                    shape = RoundedCornerShape(8.dp)
                ) {
                    if (isLoading) {
                        CircularProgressIndicator(
                            modifier = Modifier.size(20.dp),
                            color = Color.White,
                            strokeWidth = 2.dp
                        )
                    } else {
                        Text("Load Wallet & Check Balances", fontWeight = FontWeight.Bold)
                    }
                }

                Spacer(modifier = Modifier.height(16.dp))

                // Wallet List
                LazyColumn(
                    verticalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    items(wallets) { walletEntry ->
                        WalletCard(
                            wallet = walletEntry,
                            onSendClick = {
                                val supportedChains = listOf("Dash", "Zcash", "Bitcoin", "Ethereum", "Solana")
                                if (walletEntry.chain in supportedChains) {
                                    scope.launch {
                                        activeSendChain = walletEntry.chain
                                        showSendDialog = true
                                    }
                                }
                            }
                        )
                    }
                }
            }
        }

        // Send Dialog
        if (showSendDialog && activeSendChain != null) {
            var recipient by remember { mutableStateOf("") }
            var amount by remember { mutableStateOf("") }
            var isSending by remember { mutableStateOf(false) }
            var txid by remember { mutableStateOf<String?>(null) }
            var error by remember { mutableStateOf<String?>(null) }

            val onSendAction = {
                isSending = true
                scope.launch(Dispatchers.Default) {
                    try {
                        val result = if (isMock) {
                            "mock-txid-${System.currentTimeMillis()}"
                        } else {
                            when (activeSendChain) {
                                "Dash" -> unifiedWallet?.dash?.send(recipient, amount)
                                "Zcash" -> unifiedWallet?.zcash?.send(recipient, amount)
                                "Bitcoin" -> unifiedWallet?.bitcoin?.send(recipient, amount)
                                "Ethereum" -> unifiedWallet?.ethereum?.send(recipient, amount)
                                "Solana" -> unifiedWallet?.solana?.send(recipient, amount)
                                else -> "Unsupported"
                            }
                        }
                        withContext(Dispatchers.Main) {
                            txid = result
                            isSending = false
                        }
                    } catch (e: Exception) {
                        e.printStackTrace()
                        withContext(Dispatchers.Main) {
                            error = e.message
                            isSending = false
                        }
                    }
                }
            }

            if (isMock) {
                // Mock Overlay for Headless Testing
                Box(
                    modifier = Modifier
                        .fillMaxSize()
                        .background(Color.Black.copy(alpha = 0.5f))
                        .zIndex(100f)
                        .semantics { testTag = "SendDialogTag" }
                        .clickable(enabled = false) {},
                    contentAlignment = Alignment.Center
                ) {
                    Card(
                        modifier = Modifier.width(320.dp).padding(16.dp),
                        colors = CardDefaults.cardColors(containerColor = MaterialTheme.colorScheme.surface)
                    ) {
                        Column(Modifier.padding(24.dp)) {
                            Text("Send $activeSendChain", style = MaterialTheme.typography.titleLarge)
                            Spacer(Modifier.height(16.dp))
                            
                            if (txid != null) {
                                Text("Transaction Sent!", color = Color.Green, fontWeight = FontWeight.Bold)
                                Text("TXID: $txid", fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                                Spacer(Modifier.height(24.dp))
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                                    Button(onClick = { showSendDialog = false }) { Text("Close") }
                                }
                            } else if (error != null) {
                                Text("Error: $error", color = Color.Red)
                                Spacer(Modifier.height(24.dp))
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                                    Button(onClick = { showSendDialog = false }) { Text("Close") }
                                }
                            } else {
                                OutlinedTextField(
                                    value = recipient,
                                    onValueChange = { recipient = it },
                                    label = { Text("Recipient Address") },
                                    modifier = Modifier.fillMaxWidth()
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = amount,
                                    onValueChange = { amount = it },
                                    label = { Text("Amount ($activeSendChain)") },
                                    modifier = Modifier.fillMaxWidth()
                                )
                                Spacer(Modifier.height(24.dp))
                                Row(Modifier.fillMaxWidth(), horizontalArrangement = Arrangement.End) {
                                    TextButton(onClick = { if (!isSending) showSendDialog = false }) { Text("Cancel") }
                                    Spacer(Modifier.width(8.dp))
                                    Button(
                                        enabled = !isSending && recipient.isNotEmpty() && amount.isNotEmpty(),
                                        onClick = { onSendAction() }
                                    ) { Text("Send") }
                                }
                            }
                        }
                    }
                }
            } else {
                AlertDialog(
                    onDismissRequest = { if (!isSending) showSendDialog = false },
                    title = { Text("Send $activeSendChain") },
                    text = {
                        Column {
                            if (txid != null) {
                                Text("Transaction Sent!", color = Color.Green, fontWeight = FontWeight.Bold)
                                Text("TXID: $txid", fontSize = 12.sp, fontFamily = FontFamily.Monospace)
                            } else if (error != null) {
                                Text("Error: $error", color = Color.Red)
                            } else {
                                OutlinedTextField(
                                    value = recipient,
                                    onValueChange = { recipient = it },
                                    label = { Text("Recipient Address") },
                                    modifier = Modifier.fillMaxWidth()
                                )
                                Spacer(modifier = Modifier.height(8.dp))
                                OutlinedTextField(
                                    value = amount,
                                    onValueChange = { amount = it },
                                    label = { Text("Amount ($activeSendChain)") },
                                    modifier = Modifier.fillMaxWidth()
                                )
                            }
                        }
                    },
                    confirmButton = {
                        if (txid != null) {
                            Button(onClick = { showSendDialog = false }) { Text("Close") }
                        } else if (error != null) {
                             Button(onClick = { showSendDialog = false }) { Text("Close") }
                        } else {
                            Button(
                                enabled = !isSending && recipient.isNotEmpty() && amount.isNotEmpty(),
                                onClick = { onSendAction() }
                            ) { Text("Send") }
                        }
                    },
                    dismissButton = {
                        if (txid == null && error == null) {
                            TextButton(onClick = { if (!isSending) showSendDialog = false }) { Text("Cancel") }
                        }
                    }
                )
            }
        }
    }
}

@Composable
fun WalletCard(wallet: WalletEntry, onSendClick: () -> Unit) {
    Card(
        modifier = Modifier.fillMaxWidth(),
        colors = CardDefaults.cardColors(
            containerColor = Color(0xFF161B22)
        ),
        shape = RoundedCornerShape(12.dp)
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically
            ) {
                // Emoji
                Box(
                    modifier = Modifier
                        .size(48.dp)
                        .background(wallet.color.copy(alpha = 0.2f), RoundedCornerShape(12.dp)),
                    contentAlignment = Alignment.Center
                ) {
                    Text(
                        text = wallet.emoji,
                        fontSize = 24.sp
                    )
                }

                Spacer(modifier = Modifier.width(16.dp))

                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        Text(
                            text = wallet.chain,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            fontSize = 16.sp
                        )
                        Text(
                            text = wallet.balance,
                            fontWeight = FontWeight.Bold,
                            color = Color.White,
                            fontSize = 14.sp
                        )
                    }
                    
                    Text(
                        text = wallet.path,
                        color = Color.Gray,
                        fontSize = 12.sp
                    )
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = if (wallet.address.length > 42) 
                            "${wallet.address.take(20)}...${wallet.address.takeLast(8)}"
                        else wallet.address,
                        color = Color(0xFF58A6FF),
                        fontSize = 12.sp,
                        fontFamily = FontFamily.Monospace
                    )
                }
            }
            
            val supportedChains = listOf("Bitcoin", "Ethereum", "Solana", "Dash", "Zcash")
            if (wallet.chain in supportedChains) {
                Spacer(modifier = Modifier.height(12.dp))
                Button(
                    onClick = onSendClick,
                    modifier = Modifier.fillMaxWidth(),
                    colors = ButtonDefaults.buttonColors(containerColor = Color(0xFF21262D)),
                    shape = RoundedCornerShape(6.dp),
                    contentPadding = PaddingValues(4.dp)
                ) {
                    Text("Send ${wallet.chain}", fontSize = 12.sp)
                }
            }
        }
    }
}

