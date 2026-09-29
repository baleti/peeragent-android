package dev.local.peeragent

import android.util.Base64
import java.security.KeyFactory
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.security.MessageDigest
import java.util.concurrent.ConcurrentHashMap

/**
 * Verifies Ed25519-signed requests from host3 to the privileged-relay
 * endpoints specifically - a second, narrower authentication layer on top of
 * WireGuard's own peer trust (see BridgeHttpServer's class doc), since
 * install/diagnostics on our own apps is more sensitive than the existing
 * media-control endpoints. Needs API 31+ (Conscrypt's built-in "Ed25519"
 * Signature/KeyFactory algorithms); callers must guard on SDK level.
 *
 * Canonical string signed by the caller:
 *   METHOD "\n" PATH_AND_QUERY "\n" TIMESTAMP_MS "\n" NONCE "\n" base64(sha256(body))
 * PATH_AND_QUERY includes the query string (e.g. "/privileged/install?pkg=X") -
 * it must, since that's what actually determines which app a request targets.
 * Timestamp must be within [MAX_SKEW_MS] of now, and each (timestamp, nonce)
 * pair may only be seen once - both replay defenses on top of the signature
 * itself, since a captured-and-replayed genuine signature would otherwise
 * still be valid forever.
 */
object Ed25519Verify {
    // host3's public key (32 raw bytes) - see
    // ~/.config/peer-app-debugger/host3-ed25519-public.pem on host3 for the
    // matching private key, which never leaves that machine.
    private const val HOST3_PUBLIC_KEY_B64 = "2VQsTzWJ+tdltMLuanZsfMhIbsdCtIoeXL9mvANe3ok="

    // Fixed 12-byte X.509 SubjectPublicKeyInfo prefix for a raw Ed25519 key
    // (algorithm OID 1.3.101.112, no parameters) - Ed25519 keys have no
    // encoded parameters, so this prefix is always identical.
    private val SPKI_PREFIX = byteArrayOf(
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    )

    private const val MAX_SKEW_MS = 60_000L
    private const val NONCE_TTL_MS = 5 * 60_000L

    private val seenNonces = ConcurrentHashMap<String, Long>()

    private val publicKey: PublicKey by lazy {
        val raw = Base64.decode(HOST3_PUBLIC_KEY_B64, Base64.DEFAULT)
        val der = SPKI_PREFIX + raw
        KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(der))
    }

    fun available(): Boolean = android.os.Build.VERSION.SDK_INT >= 31

    /** @return null if valid, else a rejection reason string. */
    fun verify(method: String, pathAndQuery: String, timestampMs: Long, nonce: String, body: ByteArray, signatureB64: String): String? {
        if (!available()) return "Ed25519 unsupported on this API level"
        val now = System.currentTimeMillis()
        if (Math.abs(now - timestampMs) > MAX_SKEW_MS) return "timestamp outside allowed skew"
        if (nonce.isBlank() || nonce.length > 128) return "bad nonce"

        // Signature verified BEFORE the nonce is ever recorded as seen:
        // originally this was ordered the other way, which let anyone who
        // could reach this endpoint (any WireGuard peer, not just a
        // validly-signed host3 request) insert entries into the replay
        // cache using nothing but a fresh-looking timestamp+nonce and no
        // valid signature at all - an unauthenticated way to grow
        // seenNonces. Checking the signature first means only a request
        // that's already been cryptographically proven genuine ever
        // consumes a nonce slot.
        val bodyHash = MessageDigest.getInstance("SHA-256").digest(body)
        val canonical = "$method\n$pathAndQuery\n$timestampMs\n$nonce\n${Base64.encodeToString(bodyHash, Base64.NO_WRAP)}"

        val sigValid = try {
            val sig = Signature.getInstance("Ed25519")
            sig.initVerify(publicKey)
            sig.update(canonical.toByteArray(Charsets.UTF_8))
            val sigBytes = Base64.decode(signatureB64, Base64.DEFAULT)
            sig.verify(sigBytes)
        } catch (e: Exception) {
            return "signature check error: ${e.javaClass.simpleName}: ${e.message}"
        }
        if (!sigValid) return "signature verification failed"

        pruneNonces(now)
        val nonceKey = "$timestampMs:$nonce"
        if (seenNonces.putIfAbsent(nonceKey, now) != null) return "replay: nonce already used"

        return null
    }

    private fun pruneNonces(now: Long) {
        if (seenNonces.size < 10_000) return
        val cutoff = now - NONCE_TTL_MS
        seenNonces.entries.removeAll { it.value < cutoff }
    }
}
