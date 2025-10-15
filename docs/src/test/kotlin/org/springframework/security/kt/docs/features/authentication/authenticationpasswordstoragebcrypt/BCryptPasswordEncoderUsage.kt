package org.springframework.security.kt.docs.features.authentication.authenticationpasswordstoragebcrypt

import org.junit.Assert.assertTrue
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder

class BCryptPasswordEncoderUsage {
    fun testBCryptPasswordEncoder() {
        // tag::bcryptPasswordEncoder[]
        // Create an encoder with strength 16
        val encoder = BCryptPasswordEncoder(16)
        val result: String = encoder.encode("myPassword")
        assertTrue(encoder.matches("myPassword", result))
        // end::bcryptPasswordEncoder[]
    }
}
