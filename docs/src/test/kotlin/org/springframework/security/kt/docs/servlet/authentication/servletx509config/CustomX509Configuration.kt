/*
 * Copyright 2004-present the original author or authors.
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
package org.springframework.security.kt.docs.servlet.authentication.servlet509config

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.authentication.preauth.x509.SubjectX500PrincipalExtractor
import org.springframework.web.servlet.config.annotation.EnableWebMvc

/**
 * Demonstrates custom configuration for x509 reactive configuration.
 *
 * @author Rob Winch
 */
@EnableWebMvc
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class CustomX509Configuration {
    // tag::springSecurity[]
    @Bean
    fun springSecurity(http: HttpSecurity): DefaultSecurityFilterChain? {
        val principalExtractor = SubjectX500PrincipalExtractor()
        principalExtractor.setExtractPrincipalNameFromEmail(true)

        // @formatter:off
        http {
            authorizeHttpRequests {
                authorize(anyRequest, authenticated)
            }
            x509 {
                x509PrincipalExtractor = principalExtractor
            }
        }
        return http.build()
    }
    // end::springSecurity[]

    @Bean
    fun userDetailsService(): UserDetailsService {
        // @formatter:off
        val user = User
            .withUsername("luke@monkeymachine")
            .password("password")
            .roles("USER")
            .build()
        // @formatter:on
        return InMemoryUserDetailsManager(user)
    }
}
