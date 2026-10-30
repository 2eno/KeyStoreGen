package io.github.keystoregen.bitwarden

import java.io.BufferedInputStream
import java.net.InetAddress
import java.net.ServerSocket
import kotlin.concurrent.thread

/** Just enough HTTP/1.1 for HttpURLConnection: one request per connection, routed by path prefix. */
class FakeHttpServer {
    class Request(val method: String, val path: String, val headers: Map<String, String>, val body: String) {
        fun header(name: String) = headers.entries.firstOrNull { it.key.equals(name, ignoreCase = true) }?.value
    }

    private val socket = ServerSocket(0, 50, InetAddress.getByName("127.0.0.1"))
    private val routes = mutableMapOf<String, (Request) -> Pair<Int, String>>()
    val port get() = socket.localPort

    fun route(prefix: String, handler: (Request) -> Pair<Int, String>) {
        routes[prefix] = handler
    }

    fun start() = thread(isDaemon = true) {
        while (!socket.isClosed) {
            val client = runCatching { socket.accept() }.getOrNull() ?: break
            client.use { connection ->
                val input = BufferedInputStream(connection.getInputStream())
                fun line(): String = buildString {
                    while (true) {
                        val c = input.read()
                        if (c == -1 || c == '\n'.code) break
                        if (c != '\r'.code) append(c.toChar())
                    }
                }
                val (method, path) = line().split(' ').let { it[0] to it[1] }
                val headers = generateSequence(::line).takeWhile { it.isNotEmpty() }
                    .associate { it.substringBefore(':').trim() to it.substringAfter(':').trim() }
                val length = headers.entries.firstOrNull { it.key.equals("Content-Length", true) }?.value?.toInt() ?: 0
                val body = ByteArray(length).also { var n = 0; while (n < length) n += input.read(it, n, length - n) }
                val request = Request(method, path, headers, body.decodeToString())
                val (status, text) = try {
                    routes.entries.firstOrNull { path.startsWith(it.key) }?.value?.invoke(request) ?: (404 to "{}")
                } catch (e: Throwable) {
                    500 to "{\"message\":\"${e.message}\"}"
                }
                val bytes = text.toByteArray()
                connection.getOutputStream().apply {
                    write("HTTP/1.1 $status X\r\nContent-Type: application/json\r\nContent-Length: ${bytes.size}\r\nConnection: close\r\n\r\n".toByteArray())
                    write(bytes)
                    flush()
                }
            }
        }
    }

    fun stop() = socket.close()
}
