/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.web.servlet

import io.mockk.mockk
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.junit.Rule
import org.junit.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.core.io.ClassPathResource
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsByNameServiceWrapper
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.x509
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers.authenticated
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken
import org.springframework.security.web.authentication.preauth.x509.SubjectDnX509PrincipalExtractor
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get

/**
 * Tests for [X509Dsl]
 *
 * @author Eleftheria Stein
 */
class X509DslTests {
    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `x509 when configured with defaults then user authenticated`() {
        this.spring.register(X509Config::class.java).autowire()
        val certificate = loadCert<X509Certificate>("rod.cer")

        this.mockMvc.perform(get("/")
                .with(x509(certificate)))
                .andExpect(authenticated().withUsername("rod"))
    }

    @EnableWebSecurity
    open class X509Config : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                x509 { }
            }
        }

        @Bean
        override fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                    .username("rod")
                    .password("password")
                    .roles("USER")
                    .build()
            return InMemoryUserDetailsManager(userDetails)
        }
    }

    @Test
    fun `x509 when configured with regex then user authenticated`() {
        this.spring.register(X509RegexConfig::class.java).autowire()
        val certificate = loadCert<X509Certificate>("rodatexampledotcom.cer")

        this.mockMvc.perform(get("/")
                .with(x509(certificate)))
                .andExpect(authenticated().withUsername("rod"))
    }

    @EnableWebSecurity
    open class X509RegexConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            http {
                x509 {
                    subjectPrincipalRegex = "CN=(.*?)@example.com(?:,|$)"
                }
            }
        }

        @Bean
        override fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                    .username("rod")
                    .password("password")
                    .roles("USER")
                    .build()
            return InMemoryUserDetailsManager(userDetails)
        }
    }

    @Test
    fun `x509 when user details service configured then user details service used`() {
        this.spring.register(UserDetailsServiceConfig::class.java).autowire()
        val certificate = loadCert<X509Certificate>("rod.cer")

        this.mockMvc.perform(get("/")
                .with(x509(certificate)))
                .andExpect(authenticated().withUsername("rod"))
    }

    @EnableWebSecurity
    open class UserDetailsServiceConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            val userDetails = User.withDefaultPasswordEncoder()
                    .username("rod")
                    .password("password")
                    .roles("USER")
                    .build()
            val customUserDetailsService = InMemoryUserDetailsManager(userDetails)
            http {
                x509 {
                    userDetailsService = customUserDetailsService
                }
            }
        }

        @Bean
        override fun userDetailsService(): UserDetailsService = mockk()
    }

    @Test
    fun `x509 when authentication user details service configured then custom user details service used`() {
        this.spring.register(AuthenticationUserDetailsServiceConfig::class.java).autowire()
        val certificate = loadCert<X509Certificate>("rod.cer")

        this.mockMvc.perform(get("/")
                .with(x509(certificate)))
                .andExpect(authenticated().withUsername("rod"))
    }

    @EnableWebSecurity
    open class AuthenticationUserDetailsServiceConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            val userDetails = User.withDefaultPasswordEncoder()
                    .username("rod")
                    .password("password")
                    .roles("USER")
                    .build()
            val customUserDetailsService = InMemoryUserDetailsManager(userDetails)
            val customSource = UserDetailsByNameServiceWrapper<PreAuthenticatedAuthenticationToken>()
            customSource.setUserDetailsService(customUserDetailsService)
            http {
                x509 {
                    authenticationUserDetailsService = customSource
                }
            }
        }

        @Bean
        override fun userDetailsService(): UserDetailsService = mockk()
    }

    @Test
    fun `x509 when configured with principal extractor then principal extractor used`() {
        this.spring.register(X509PrincipalExtractorConfig::class.java).autowire()
        val certificate = loadCert<X509Certificate>("rodatexampledotcom.cer")

        this.mockMvc.perform(get("/")
                .with(x509(certificate)))
                .andExpect(authenticated().withUsername("rod"))
    }

    @EnableWebSecurity
    open class X509PrincipalExtractorConfig : WebSecurityConfigurerAdapter() {
        override fun configure(http: HttpSecurity) {
            val principalExtractor = SubjectDnX509PrincipalExtractor()
            principalExtractor.setSubjectDnRegex("CN=(.*?)@example.com(?:,|$)")
            http {
                x509 {
                    x509PrincipalExtractor = principalExtractor
                }
            }
        }

        @Bean
        override fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                    .username("rod")
                    .password("password")
                    .roles("USER")
                    .build()
            return InMemoryUserDetailsManager(userDetails)
        }
    }

    private fun <T : Certificate> loadCert(location: String): T {
        ClassPathResource(location).inputStream.use { inputStream ->
            val certFactory = CertificateFactory.getInstance("X.509")
            return certFactory.generateCertificate(inputStream) as T
        }
    }
}
