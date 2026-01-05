package com.clara.security.ipc

import android.net.LocalSocket
import android.net.LocalSocketAddress
import android.util.Log
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.DataInputStream
import java.io.DataOutputStream
import java.io.IOException
import java.nio.ByteBuffer
import java.nio.ByteOrder

/**
 * CLARA Daemon IPC Client
 *
 * Communicates with the native daemon via Unix Domain Socket.
 * Protocol: Binary header (8 bytes) + payload
 */
object DaemonIpcClient {
    private const val TAG = "DaemonIpcClient"
    
    // Socket path (matches ipc_server.cpp)
    private const val SOCKET_PATH = "/dev/socket/clara_daemon"
    private const val ABSTRACT_SOCKET = "@clara_daemon"
    
    // Protocol constants (must match ipc_server.h)
    private const val IPC_MAGIC_0: Byte = 'C'.code.toByte()
    private const val IPC_MAGIC_1: Byte = 'L'.code.toByte()
    private const val IPC_VERSION: Byte = 0x01
    
    // Command codes
    object Command {
        const val PING: Byte = 0x01
        const val GET_STATUS: Byte = 0x02
        const val START_SCAN: Byte = 0x10
        const val STOP_SCAN: Byte = 0x11
        const val GET_THREATS: Byte = 0x20
        const val QUARANTINE_FILE: Byte = 0x30
        const val BLOCK_APP: Byte = 0x40
        const val UNBLOCK_APP: Byte = 0x41
        const val SET_AUTONOMOUS_MODE: Byte = 0x50
        const val RESPONSE_OK: Byte = 0xF0.toByte()
        const val RESPONSE_ERROR: Byte = 0xFF.toByte()
    }
    
    // Connection state
    private var socket: LocalSocket? = null
    private var outputStream: DataOutputStream? = null
    private var inputStream: DataInputStream? = null
    
    /**
     * Connect to the daemon
     */
    suspend fun connect(): Boolean = withContext(Dispatchers.IO) {
        try {
            disconnect() // Close existing connection
            
            socket = LocalSocket()
            
            // Try abstract namespace first, then filesystem path
            try {
                val address = LocalSocketAddress(ABSTRACT_SOCKET.substring(1), LocalSocketAddress.Namespace.ABSTRACT)
                socket?.connect(address)
                Log.d(TAG, "Connected via abstract namespace")
            } catch (e: IOException) {
                // Fallback to filesystem socket
                val address = LocalSocketAddress(SOCKET_PATH, LocalSocketAddress.Namespace.FILESYSTEM)
                socket?.connect(address)
                Log.d(TAG, "Connected via filesystem socket")
            }
            
            outputStream = DataOutputStream(socket!!.outputStream)
            inputStream = DataInputStream(socket!!.inputStream)
            
            // Send ping to verify connection
            val pong = sendCommand(Command.PING)
            if (pong != null) {
                Log.i(TAG, "Daemon connection established")
                return@withContext true
            }
            
            return@withContext false
        } catch (e: Exception) {
            Log.e(TAG, "Failed to connect to daemon", e)
            return@withContext false
        }
    }
    
    /**
     * Disconnect from the daemon
     */
    fun disconnect() {
        try {
            inputStream?.close()
            outputStream?.close()
            socket?.close()
        } catch (e: Exception) {
            Log.w(TAG, "Error during disconnect", e)
        } finally {
            inputStream = null
            outputStream = null
            socket = null
        }
    }
    
    /**
     * Check if connected
     */
    fun isConnected(): Boolean {
        return socket?.isConnected == true
    }
    
    /**
     * Send a command to the daemon
     * 
     * @param command Command byte
     * @param payload Optional payload string
     * @return Response payload or null on error
     */
    suspend fun sendCommand(command: Byte, payload: String = ""): String? = withContext(Dispatchers.IO) {
        val out = outputStream ?: return@withContext null
        val inp = inputStream ?: return@withContext null
        
        try {
            val payloadBytes = payload.toByteArray(Charsets.UTF_8)
            
            // Build header (8 bytes)
            val header = ByteBuffer.allocate(8).order(ByteOrder.LITTLE_ENDIAN)
            header.put(IPC_MAGIC_0)
            header.put(IPC_MAGIC_1)
            header.put(IPC_VERSION)
            header.put(command)
            header.putShort(payloadBytes.size.toShort())
            header.putShort(0) // Reserved
            
            // Send header + payload
            synchronized(out) {
                out.write(header.array())
                if (payloadBytes.isNotEmpty()) {
                    out.write(payloadBytes)
                }
                out.flush()
            }
            
            // Read response header (8 bytes)
            val responseHeader = ByteArray(8)
            synchronized(inp) {
                inp.readFully(responseHeader)
            }
            
            // Parse response header
            val respBuffer = ByteBuffer.wrap(responseHeader).order(ByteOrder.LITTLE_ENDIAN)
            val magic0 = respBuffer.get()
            val magic1 = respBuffer.get()
            val version = respBuffer.get()
            val respCommand = respBuffer.get()
            val respPayloadLen = respBuffer.short.toInt() and 0xFFFF
            
            // Validate magic
            if (magic0 != IPC_MAGIC_0 || magic1 != IPC_MAGIC_1) {
                Log.e(TAG, "Invalid response magic")
                return@withContext null
            }
            
            // Read response payload
            val responsePayload = if (respPayloadLen > 0) {
                val payloadBuffer = ByteArray(respPayloadLen)
                synchronized(inp) {
                    inp.readFully(payloadBuffer)
                }
                String(payloadBuffer, Charsets.UTF_8)
            } else {
                ""
            }
            
            if (respCommand == Command.RESPONSE_ERROR) {
                Log.w(TAG, "Daemon returned error: $responsePayload")
                return@withContext null
            }
            
            return@withContext responsePayload
            
        } catch (e: Exception) {
            Log.e(TAG, "IPC communication error", e)
            disconnect()
            return@withContext null
        }
    }
    
    // =========================================================================
    // High-level API
    // =========================================================================
    
    /**
     * Ping the daemon to check if it's alive
     */
    suspend fun ping(): Boolean {
        return sendCommand(Command.PING) != null
    }
    
    /**
     * Get daemon status (version, active modules, etc.)
     */
    suspend fun getStatus(): String? {
        return sendCommand(Command.GET_STATUS)
    }
    
    /**
     * Start a full security scan
     */
    suspend fun startScan(): Boolean {
        return sendCommand(Command.START_SCAN) != null
    }
    
    /**
     * Stop the current scan
     */
    suspend fun stopScan(): Boolean {
        return sendCommand(Command.STOP_SCAN) != null
    }
    
    /**
     * Get recent threats (JSON format)
     */
    suspend fun getRecentThreats(): String? {
        return sendCommand(Command.GET_THREATS)
    }
    
    /**
     * Quarantine a specific file
     */
    suspend fun quarantineFile(filePath: String): Boolean {
        return sendCommand(Command.QUARANTINE_FILE, filePath) != null
    }
    
    /**
     * Block an app's network access
     */
    suspend fun blockApp(packageName: String): Boolean {
        return sendCommand(Command.BLOCK_APP, packageName) != null
    }
    
    /**
     * Unblock an app's network access
     */
    suspend fun unblockApp(packageName: String): Boolean {
        return sendCommand(Command.UNBLOCK_APP, packageName) != null
    }
    
    /**
     * Enable or disable autonomous threat response
     */
    suspend fun setAutonomousMode(enabled: Boolean): Boolean {
        return sendCommand(Command.SET_AUTONOMOUS_MODE, if (enabled) "1" else "0") != null
    }
}
