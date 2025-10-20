package org.springframework.security.kt.docs.features.authentication.authenticationpasswordstorageargon2

import org.junit.Assert.assertTrue
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder

class Argon2PasswordEncoderUsage {
    fun testArgon2PasswordEncoder() {
        // tag::argon2PasswordEncoder[]
        // Create an encoder with all the defaults
        val encoder = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        val result: String? = encoder.encode("myPassword")
        assertTrue(encoder.matches("myPassword", result))
        // end::argon2PasswordEncoder[]
    }
}
