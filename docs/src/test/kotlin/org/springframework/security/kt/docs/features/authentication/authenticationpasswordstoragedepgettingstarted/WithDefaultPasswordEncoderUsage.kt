package org.springframework.security.kt.docs.features.authentication.authenticationpasswordstoragedepgettingstarted

import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetails

class WithDefaultPasswordEncoderUsage {

    @Suppress("DEPRECATION")
    fun createSingleUser(): UserDetails {
        // tag::createSingleUser[]
        val user = User.withDefaultPasswordEncoder()
            .username("user")
            .password("password")
            .roles("user")
            .build()
        println(user.password)
        // {bcrypt}$2a$10$dXJ3SW6G7P50lGmMkkmwe.20cQQubK3.HZWzG3YB1tlRy.fqvM/BG
        // end::createSingleUser[]
        return user
    }

    @Suppress("DEPRECATION")
    fun createMultipleUsers(): List<UserDetails> {
        // tag::createMultipleUsers[]
        val users = User.withDefaultPasswordEncoder()
        val user = users
            .username("user")
            .password("password")
            .roles("USER")
            .build()
        val admin = users
            .username("admin")
            .password("password")
            .roles("USER", "ADMIN")
            .build()
        // end::createMultipleUsers[]
        return listOf(user, admin)
    }
}
