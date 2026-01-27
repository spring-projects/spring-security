package org.springframework.security.kt.docs.features.authentication.authenticationpasswordstoragedpe

import org.springframework.security.crypto.argon2.Argon2PasswordEncoder
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.factory.PasswordEncoderFactories
import org.springframework.security.crypto.password.DelegatingPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.crypto.password.Pbkdf2PasswordEncoder
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder

class DelegatingPasswordEncoderUsage {
    fun defaultDelegatingPasswordEncoder(): PasswordEncoder {
        // tag::createDefaultPasswordEncoder[]
        val passwordEncoder: PasswordEncoder = PasswordEncoderFactories.createDelegatingPasswordEncoder()
        // end::createDefaultPasswordEncoder[]
        return passwordEncoder
    }

    @Suppress("DEPRECATION")
    fun customDelegatingPasswordEncoder(): PasswordEncoder {
        // tag::createCustomPasswordEncoder[]
        val idForEncode = "bcrypt"
        val encoders: MutableMap<String, PasswordEncoder> = mutableMapOf()
        encoders[idForEncode] = BCryptPasswordEncoder()
        encoders["noop"] = org.springframework.security.crypto.password.NoOpPasswordEncoder.getInstance()
        encoders["pbkdf2"] = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_5()
        encoders["pbkdf2@SpringSecurity_v5_8"] = Pbkdf2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        encoders["scrypt"] = SCryptPasswordEncoder.defaultsForSpringSecurity_v4_1()
        encoders["scrypt@SpringSecurity_v5_8"] = SCryptPasswordEncoder.defaultsForSpringSecurity_v5_8()
        encoders["argon2"] = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_2()
        encoders["argon2@SpringSecurity_v5_8"] = Argon2PasswordEncoder.defaultsForSpringSecurity_v5_8()
        encoders["sha256"] = org.springframework.security.crypto.password.StandardPasswordEncoder()

        val passwordEncoder: PasswordEncoder = DelegatingPasswordEncoder(idForEncode, encoders)
        // end::createCustomPasswordEncoder[]
        return passwordEncoder
    }
}
