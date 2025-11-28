package org.springframework.security.kt.docs.features.authentication.password4jbcrypt

import com.password4j.BcryptFunction
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password4j.BcryptPassword4jPasswordEncoder

/**
 * @author Rob Winch
 */
class BcryptUsageTests {
    @Test
    fun defaultParams() {
        // tag::default-params[]
        val encoder: PasswordEncoder = BcryptPassword4jPasswordEncoder()
        val result = encoder.encode("myPassword")
        Assertions.assertThat(encoder.matches("myPassword", result)).isTrue()
        // end::default-params[]
    }

    @Test
    fun customParameters() {
        // tag::custom-params[]
        val bcryptFunction = BcryptFunction.getInstance(12)
        val encoder: PasswordEncoder = BcryptPassword4jPasswordEncoder(bcryptFunction)
        val result = encoder.encode("myPassword")
        Assertions.assertThat(encoder.matches("myPassword", result)).isTrue()
        // end::custom-params[]
    }
}
