/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.client.OidcBackChannelLogoutHandler
import org.springframework.security.config.annotation.web.oauth2.login.OidcBackChannelLogoutDsl
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.oauth2.client.oidc.session.InMemoryOidcSessionRegistry
import org.springframework.security.oauth2.client.oidc.session.OidcSessionRegistry
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.TestClientRegistrations
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.test.util.ReflectionTestUtils
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.post

/**
 * Tests for [OAuth2ClientDsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class OidcLogoutDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `oidcLogout when invalid token then errors`() {
        this.spring.register(ClientRepositoryConfig::class.java).autowire()
        val clientRegistration = this.spring.context.getBean(ClientRegistration::class.java)
        this.mockMvc.post("/logout/connect/back-channel/" + clientRegistration.registrationId) {
            param("logout_token", "token")
        }.andExpect { status { isBadRequest() } }
        val chain: SecurityFilterChain = this.spring.context.getBean(SecurityFilterChain::class.java)
        for (filter in chain.filters) {
            if (filter.javaClass.simpleName.equals("OidcBackChannelLogoutFilter")) {
                val logoutHandler = ReflectionTestUtils.getField(filter, "logoutHandler") as LogoutHandler
                val backChannelLogoutHandler = ReflectionTestUtils.getField(logoutHandler, "left") as LogoutHandler
                var cookieName = ReflectionTestUtils.getField(backChannelLogoutHandler, "sessionCookieName") as String
                assert(cookieName.equals("SESSION"))
            }
        }
    }

    @Configuration
    @EnableWebSecurity
    open class ClientRepositoryConfig {

        private val sessionRegistry = InMemoryOidcSessionRegistry()

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2Login { }
                oidcLogout {
                    backChannel { }
                }
                authorizeHttpRequests {
                    authorize(anyRequest, authenticated)
                }
            }
            return http.build()
        }

        @Bean
        open fun oidcLogoutHandler(): OidcBackChannelLogoutHandler {
            val logoutHandler = OidcBackChannelLogoutHandler(this.sessionRegistry)
            logoutHandler.setSessionCookieName("SESSION");
            return logoutHandler;
        }

        @Bean
        open fun clientRegistration(): ClientRegistration {
            return TestClientRegistrations.clientRegistration().build()
        }

        @Bean
        open fun clientRegistrationRepository(clientRegistration: ClientRegistration): ClientRegistrationRepository {
            return InMemoryClientRegistrationRepository(clientRegistration)
        }
    }

}
