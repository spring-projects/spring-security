package org.springframework.security.kt.docs.features.authentication.password4jscrypt

import com.password4j.ScryptFunction
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password4j.ScryptPassword4jPasswordEncoder

/**
 * @author Rob Winch
 */
class ScryptUsageTests {
    @Test
    fun defaultParams() {
        // tag::default-params[]
        val encoder: PasswordEncoder = ScryptPassword4jPasswordEncoder()
        val result = encoder.encode("myPassword")
        Assertions.assertThat(encoder.matches("myPassword", result)).isTrue()
        // end::default-params[]
    }

    @Test
    fun customParameters() {
        // tag::custom-params[]
        val scryptFn = ScryptFunction.getInstance(32768, 8, 1, 32)
        val encoder: PasswordEncoder = ScryptPassword4jPasswordEncoder(scryptFn)
        val result = encoder.encode("myPassword")
        Assertions.assertThat(encoder.matches("myPassword", result)).isTrue()
        // end::custom-params[]
    }
}
