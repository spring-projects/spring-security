package org.springframework.security.kt.docs.features.authentication.authenticationpasswordstoragepbkdf2

import org.junit.Assert.assertTrue
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder

class Pbkdf2PasswordEncoderUsage {
    fun testPbkdf2PasswordEncoder() {
        // tag::pbkdf2PasswordEncoder[]
        // Create an encoder with all the defaults
        val encoder = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        val result: String = encoder.encode("myPassword")
        assertTrue(encoder.matches("myPassword", result))
        // end::pbkdf2PasswordEncoder[]
    }
}
