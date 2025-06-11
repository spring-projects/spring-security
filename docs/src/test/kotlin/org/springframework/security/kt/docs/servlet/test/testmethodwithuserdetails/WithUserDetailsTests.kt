/*
 * Copyright 2002-2025 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.kt.docs.servlet.test.testmethodwithuserdetails

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity
import org.springframework.security.config.core.MessageService
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.kt.docs.servlet.test.testmethod.HelloMessageService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.test.context.support.WithUserDetails
import org.springframework.test.context.ContextConfiguration
import org.springframework.test.context.junit.jupiter.SpringExtension

@ExtendWith(SpringExtension::class)
@ContextConfiguration
class WithUserDetailsTests {

    @Autowired
    lateinit var messageService: MessageService

    // tag::user-details[]
    @Test
    @WithUserDetails
    fun getMessageWithUserDetails() {
        val message: String = messageService.message
        Assertions.assertThat(message).contains("user")
    }
    // end::user-details[]

    // tag::user-details-custom-username[]
    @Test
    @WithUserDetails("customUsername")
    fun getMessageWithUserDetailsCustomUsername() {
        val message: String = messageService.message
        Assertions.assertThat(message).contains("customUsername")
    }
    // end::user-details-custom-username[]

    @EnableMethodSecurity
    @Configuration
    open class Config {

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val user1 = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .build();
            val customUser = User.withDefaultPasswordEncoder()
                .username("customUsername")
                .password("password")
                .build();
            return InMemoryUserDetailsManager(user1, customUser);
        }

        @Bean
        open fun messageService(): MessageService {
            return HelloMessageService()
        }
    }
}
