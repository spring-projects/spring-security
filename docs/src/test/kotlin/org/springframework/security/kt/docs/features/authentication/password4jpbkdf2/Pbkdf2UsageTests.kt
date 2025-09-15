package org.springframework.security.kt.docs.features.authentication.password4jpbkdf2

import com.password4j.PBKDF2Function
import com.password4j.types.Hmac
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password4j.Pbkdf2Password4jPasswordEncoder

/**
 * @author Rob Winch
 */
class Pbkdf2UsageTests {
    @Test
    fun defaultParams() {
        // tag::default-params[]
        val encoder: PasswordEncoder = Pbkdf2Password4jPasswordEncoder()
        val result = encoder.encode("myPassword")
        Assertions.assertThat(encoder.matches("myPassword", result)).isTrue()
        // end::default-params[]
    }

    @Test
    fun customParameters() {
        // tag::custom-params[]
        val pbkdf2Fn = PBKDF2Function.getInstance(Hmac.SHA256, 100000, 256)
        val encoder: PasswordEncoder = Pbkdf2Password4jPasswordEncoder(pbkdf2Fn)
        val result = encoder.encode("myPassword")
        Assertions.assertThat(encoder.matches("myPassword", result)).isTrue()
        // end::custom-params[]
    }
}
