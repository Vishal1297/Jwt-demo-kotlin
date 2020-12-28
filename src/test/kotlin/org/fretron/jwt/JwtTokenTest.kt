package org.fretron.jwt

import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert
import org.junit.Before
import org.junit.Test
import java.security.NoSuchAlgorithmException
import java.time.LocalDateTime
import java.time.ZoneOffset


/**
 * @author user
 */
class JWebTokenTest {

    private lateinit var ldt: LocalDateTime
    private lateinit var payload: JSONObject

    @Before
    fun setUp() {
        ldt = LocalDateTime.now().plusDays(90)
        payload = JSONObject(
            "{\"sub\":\"1234\",\"aud\":[\"admin\"],"
                    + "\"exp\":" + ldt.toEpochSecond(ZoneOffset.UTC) + "}"
        )
    }

    @After
    fun tearDown() {
    }

    /**
     * Test of HMACSHA256 method, of class JWebToken.
     */
    @Test
    fun testWithData() {
        //generate JWT
        val exp = LocalDateTime.now().plusDays(90).toEpochSecond(ZoneOffset.UTC)
        val token = JWebToken("1234", JSONArray("['admin']"), exp).toString()
        //verify and use
        println("testWithData ::\n $token")
        try {
            val incomingToken = JWebToken(token)
            if (incomingToken.isValid) {
                Assert.assertEquals("1234", incomingToken.subject)
                Assert.assertEquals("admin", incomingToken.audience[0])
            }
        } catch (ex: NoSuchAlgorithmException) {
            Assert.fail("Invalid Token" + ex.message)
        }
    }

    @Test
    fun testWithJson() {
        val token = JWebToken((payload)).toString()
        //verify and use
        val incomingToken: JWebToken
        try {
            incomingToken = JWebToken(token)
            if (incomingToken.isValid) {
                Assert.assertEquals("1234", incomingToken.subject)
                Assert.assertEquals("admin", incomingToken.audience[0])
            }
        } catch (ex: NoSuchAlgorithmException) {
            Assert.fail("Invalid Token" + ex.message)
        }
    }

    @Test(expected = IllegalArgumentException::class)
    fun testBadHeaderFormat() {
        var token = JWebToken((payload)).toString()
        token = token.replace("\\.".toRegex(), "X")
        //verify and use
        val incomingToken: JWebToken
        try {
            incomingToken = JWebToken(token)
            if (incomingToken.isValid) {
                Assert.assertEquals("1234", incomingToken.subject)
                Assert.assertEquals("admin", incomingToken.audience[0])
            }
        } catch (ex: NoSuchAlgorithmException) {
            Assert.fail("Invalid Token" + ex.message)
        }
    }

    @Test(expected = NoSuchAlgorithmException::class)
    @Throws(NoSuchAlgorithmException::class)
    fun testIncorrectHeader() {
        var token = JWebToken((payload)).toString()
        token = token.replace("[^.]".toRegex(), "X")
        //verify and use
        val incomingToken = JWebToken(token)
        if (incomingToken.isValid) {
            Assert.assertEquals("1234", incomingToken.subject)
            Assert.assertEquals("admin", incomingToken.audience[0])
        }
    }
}