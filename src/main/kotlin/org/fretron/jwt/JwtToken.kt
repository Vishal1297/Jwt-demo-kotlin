package org.fretron.jwt

import org.json.JSONArray
import org.json.JSONException
import org.json.JSONObject
import java.nio.charset.StandardCharsets
import java.security.InvalidKeyException
import java.security.NoSuchAlgorithmException
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.*
import java.util.logging.Level
import java.util.logging.Logger
import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 *
 * @author user
 */
class JWebToken private constructor() {
    private var payload: JSONObject = JSONObject()
    private var signature: String? = null
    private var encodedHeader: String

    init {
        encodedHeader = encode(JSONObject(JWT_HEADER))
    }

    constructor(sub: String?, aud: JSONArray?, expires: Long) : this() {
        payload.put("sub", sub)
        payload.put("aud", aud)
        payload.put("exp", expires)
        payload.put("iat", LocalDateTime.now().toEpochSecond(ZoneOffset.UTC))
        payload.put("iss", ISSUER)
        payload.put("jti", UUID.randomUUID().toString()) //how do we use this?
        signature = hmacSha256(encodedHeader + "." + encode(payload), SECRET_KEY)
    }

    constructor(payload: JSONObject) : this(
        payload.getString("sub"),
        payload.getJSONArray("aud"),
        payload.getLong("exp")
    )

    companion object {
        private val SECRET_KEY: String = "FREE_MASON" //@TODO Add Signature here
        private val HEX_ARRAY: CharArray = "0123456789ABCDEF".toCharArray()
        private val ISSUER: String = "mason.metamug.net"
        private val JWT_HEADER: String = "{\"alg\":\"HS256\",\"typ\":\"JWT\"}"
        private fun encode(obj: JSONObject): String {
            return encode(obj.toString().toByteArray(StandardCharsets.UTF_8))
        }

        private fun encode(bytes: ByteArray): String {
            return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
        }

        private fun decode(encodedString: String): String {
            return String(Base64.getUrlDecoder().decode(encodedString))
        }
    }

    /**
     * For verification
     *
     * @param token
     * @throws java.security.NoSuchAlgorithmException
     */
    constructor(token: String) : this() {
        val parts: Array<String> = token.split("\\.").toTypedArray()
        if (parts.size != 3) {
            throw IllegalArgumentException("Invalid Token format")
        }
        if ((encodedHeader == parts.get(0))) {
            encodedHeader = parts.get(0)
        } else {
            throw NoSuchAlgorithmException("JWT Header is Incorrect: " + parts.get(0))
        }
        payload = JSONObject(decode(parts.get(1)))
        if (payload.isEmpty) {
            throw JSONException("Payload is Empty: ")
        }
        if (!payload.has("exp")) {
            throw JSONException("Payload doesn't contain expiry $payload")
        }
        signature = parts.get(2)
    }

    override fun toString(): String {
        return encodedHeader + "." + encode(payload) + "." + signature
    }

    //token not expired
    //signature matched
    val isValid: Boolean
        get() = (payload.getLong("exp") > (LocalDateTime.now().toEpochSecond(ZoneOffset.UTC)) //token not expired
                && (signature == hmacSha256(encodedHeader + "." + encode(payload), SECRET_KEY)) //signature matched
                )

    val subject: String
        get() {
            return payload.getString("sub")
        }

    val audience: List<String>
        get() {
            val arr: JSONArray = payload.getJSONArray("aud")
            val list: MutableList<String> = ArrayList()
            for (i in 0 until arr.length()) {
                list.add(arr.getString(i))
            }
            return list
        }

    /**
     * Sign with HMAC SHA256 (HS256)
     *
     * @param data
     * @return
     * @throws Exception
     */
    private fun hmacSha256(data: String, secret: String): String? {
        try {

            //MessageDigest digest = MessageDigest.getInstance("SHA-256");
            val hash: ByteArray =
                secret.toByteArray(StandardCharsets.UTF_8) //digest.digest(secret.getBytes(StandardCharsets.UTF_8));
            val sha256Hmac: Mac = Mac.getInstance("HmacSHA256")
            val secretKey = SecretKeySpec(hash, "HmacSHA256")
            sha256Hmac.init(secretKey)
            val signedBytes: ByteArray = sha256Hmac.doFinal(data.toByteArray(StandardCharsets.UTF_8))
            return encode(signedBytes)
        } catch (ex: NoSuchAlgorithmException) {
            Logger.getLogger(JWebToken::class.java.name).log(Level.SEVERE, ex.message, ex)
            return null
        } catch (ex: InvalidKeyException) {
            Logger.getLogger(JWebToken::class.java.name).log(Level.SEVERE, ex.message, ex)
            return null
        }
    }
}