package org.springframework.security.kt.docs.features.authentication.authenticationpasswordstoragescrypt

import org.junit.Assert.assertTrue
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder

class SCryptPasswordEncoderUsage {
    fun testSCryptPasswordEncoder() {
        // tag::sCryptPasswordEncoder[]
        // Create an encoder with all the defaults
        val encoder = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8()
        val result: String? = encoder.encode("myPassword")
        assertTrue(encoder.matches("myPassword", result))
        // end::sCryptPasswordEncoder[]
    }
}
