/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.web.server

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.oauth2.client.oidc.server.session.InMemoryReactiveOidcSessionRegistry
import org.springframework.security.oauth2.client.registration.ClientRegistration
import org.springframework.security.oauth2.client.registration.InMemoryReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.TestClientRegistrations
import org.springframework.security.web.authentication.logout.LogoutHandler
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.test.util.ReflectionTestUtils
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.server.WebFilter

/**
 * Tests for [ServerOidcLogoutDsl]
 *
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerOidcLogoutDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    private lateinit var client: WebTestClient

    @Autowired
    fun setup(context: ApplicationContext) {
        this.client = WebTestClient
                .bindToApplicationContext(context)
                .configureClient()
                .build()
    }

    @Test
    fun `oidcLogout when invalid token then errors`() {
        this.spring.register(ClientRepositoryConfig::class.java).autowire()
        val clientRegistration = this.spring.context.getBean(ClientRegistration::class.java)
        this.client.post()
                .uri("/logout/connect/back-channel/" + clientRegistration.registrationId)
                .body(BodyInserters.fromFormData("logout_token", "token"))
                .exchange()
                .expectStatus().isBadRequest
        val chain: SecurityWebFilterChain = this.spring.context.getBean(SecurityWebFilterChain::class.java)
        chain.webFilters.doOnNext({ filter: WebFilter ->
            if (filter.javaClass.simpleName.equals("OidcBackChannelLogoutWebFilter")) {
                val logoutHandler = ReflectionTestUtils.getField(filter, "logoutHandler") as LogoutHandler
                val backChannelLogoutHandler = ReflectionTestUtils.getField(logoutHandler, "left") as LogoutHandler
                var cookieName = ReflectionTestUtils.getField(backChannelLogoutHandler, "sessionCookieName") as String
                assert(cookieName.equals("SESSION"))
            }
        })
    }

    @Configuration
    @EnableWebFlux
    @EnableWebFluxSecurity
    open class ClientRepositoryConfig {

        private val sessionRegistry = InMemoryReactiveOidcSessionRegistry()

        @Bean
        open fun securityFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                oauth2Login { }
                oidcLogout {
                    backChannel { }
                }
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
            }
        }

        @Bean
        open fun oidcLogoutHandler(): OidcBackChannelServerLogoutHandler {
            val logoutHandler = OidcBackChannelServerLogoutHandler(this.sessionRegistry)
            logoutHandler.setSessionCookieName("SESSION");
            return logoutHandler;
        }

        @Bean
        open fun clientRegistration(): ClientRegistration {
            return TestClientRegistrations.clientRegistration().build()
        }

        @Bean
        open fun clientRegistrationRepository(clientRegistration: ClientRegistration): ReactiveClientRegistrationRepository {
            return InMemoryReactiveClientRegistrationRepository(clientRegistration)
        }
    }

}
