/*
 * Copyright 2002-2024 the original author or authors.
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

import org.junit.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.ApplicationContext
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.http.MediaType
import org.springframework.http.ResponseCookie
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.config.users.ReactiveAuthenticationTestConfiguration
import org.springframework.security.core.session.InMemoryReactiveSessionRegistry
import org.springframework.security.core.session.ReactiveSessionRegistry
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.InvalidateLeastUsedServerMaximumSessionsExceededHandler
import org.springframework.security.web.server.authentication.PreventLoginServerMaximumSessionsExceededHandler
import org.springframework.security.web.server.authentication.SessionLimit
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.util.LinkedMultiValueMap
import org.springframework.util.MultiValueMap
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.server.adapter.WebHttpHandlerBuilder
import org.springframework.web.server.session.DefaultWebSessionManager

/**
 * Tests for [ServerSessionManagementDsl]
 *
 * @author Marcus da Coregio
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerSessionManagementDslTests {

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
    fun `login when max sessions prevent login then second login fails`() {
        this.spring.register(ConcurrentSessionsMaxSessionPreventsLoginTrueConfig::class.java).autowire()

        val data: MultiValueMap<String, String> = LinkedMultiValueMap()
        data.add("username", "user")
        data.add("password", "password")

        val firstLoginSessionCookie = loginReturningCookie(data)

        // second login should fail
        this.client.mutateWith(SecurityMockServerConfigurers.csrf())
            .post()
            .uri("/login")
            .contentType(MediaType.MULTIPART_FORM_DATA)
            .body(BodyInserters.fromFormData(data))
            .exchange()
            .expectHeader()
            .location("/login?error")

        // first login should still be valid
        this.client.mutateWith(SecurityMockServerConfigurers.csrf())
            .get()
            .uri("/")
            .cookie(firstLoginSessionCookie!!.name, firstLoginSessionCookie.value)
            .exchange()
            .expectStatus()
            .isOk()
    }

    @Test
    fun `login when max sessions does not prevent login then seconds login succeeds and first session is invalidated`() {
        ConcurrentSessionsMaxSessionPreventsLoginFalseConfig.maxSessions = 1
        this.spring.register(SessionManagementSpecTests.ConcurrentSessionsMaxSessionPreventsLoginFalseConfig::class.java)
            .autowire()

        val data: MultiValueMap<String, String> = LinkedMultiValueMap()
        data.add("username", "user")
        data.add("password", "password")

        val firstLoginSessionCookie = loginReturningCookie(data)
        val secondLoginSessionCookie = loginReturningCookie(data)

        // first login should not be valid
        this.client.get()
            .uri("/")
            .cookie(firstLoginSessionCookie!!.name, firstLoginSessionCookie.value)
            .exchange()
            .expectStatus()
            .isFound()
            .expectHeader()
            .location("/login")

        // second login should be valid
        this.client.get()
            .uri("/")
            .cookie(secondLoginSessionCookie!!.name, secondLoginSessionCookie.value)
            .exchange()
            .expectStatus()
            .isOk()
    }

    @Test
    fun `login when max sessions does not prevent login then least recently used session is invalidated`() {
        ConcurrentSessionsMaxSessionPreventsLoginFalseConfig.maxSessions = 2
        this.spring.register(ConcurrentSessionsMaxSessionPreventsLoginFalseConfig::class.java).autowire()
        val data: MultiValueMap<String, String> = LinkedMultiValueMap()
        data.add("username", "user")
        data.add("password", "password")
        val firstLoginSessionCookie = loginReturningCookie(data)
        val secondLoginSessionCookie = loginReturningCookie(data)

        // update last access time for first request
        this.client.get()
            .uri("/")
            .cookie(firstLoginSessionCookie!!.name, firstLoginSessionCookie.value)
            .exchange()
            .expectStatus()
            .isOk()
        val thirdLoginSessionCookie = loginReturningCookie(data)

        // second login should be invalid, it is the least recently used session
        this.client.get()
            .uri("/")
            .cookie(secondLoginSessionCookie!!.name, secondLoginSessionCookie.value)
            .exchange()
            .expectStatus()
            .isFound()
            .expectHeader()
            .location("/login")

        // first login should be valid
        this.client.get()
            .uri("/")
            .cookie(firstLoginSessionCookie.name, firstLoginSessionCookie.value)
            .exchange()
            .expectStatus()
            .isOk()

        // third login should be valid
        this.client.get()
            .uri("/")
            .cookie(thirdLoginSessionCookie!!.name, thirdLoginSessionCookie.value)
            .exchange()
            .expectStatus()
            .isOk()
    }

    private fun loginReturningCookie(data: MultiValueMap<String, String>): ResponseCookie? {
        return login(data).expectCookie()
            .exists("SESSION")
            .returnResult(Void::class.java)
            .responseCookies
            .getFirst("SESSION")
    }

    private fun login(data: MultiValueMap<String, String>): WebTestClient.ResponseSpec {
        return client.mutateWith(SecurityMockServerConfigurers.csrf())
            .post()
            .uri("/login")
            .contentType(MediaType.MULTIPART_FORM_DATA)
            .body(BodyInserters.fromFormData(data))
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .expectHeader()
            .location("/")
    }

    @Configuration
    @EnableWebFlux
    @EnableWebFluxSecurity
    @Import(Config::class)
    open class ConcurrentSessionsMaxSessionPreventsLoginFalseConfig {

        companion object {
            var maxSessions = 1
        }

        @Bean
        open fun springSecurity(http: ServerHttpSecurity, webSessionManager: DefaultWebSessionManager): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                formLogin { }
                sessionManagement {
                    sessionConcurrency {
                        maximumSessions = SessionLimit.of(maxSessions)
                        maximumSessionsExceededHandler = InvalidateLeastUsedServerMaximumSessionsExceededHandler(webSessionManager.sessionStore)
                    }
                }
            }
        }

    }

    @Configuration
    @EnableWebFlux
    @EnableWebFluxSecurity
    @Import(Config::class)
    open class ConcurrentSessionsMaxSessionPreventsLoginTrueConfig {

        @Bean
        open fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                formLogin { }
                sessionManagement {
                    sessionConcurrency {
                        maximumSessions = SessionLimit.of(1)
                        maximumSessionsExceededHandler =
                            PreventLoginServerMaximumSessionsExceededHandler()
                    }
                }
            }
        }

    }

    @Configuration
    @Import(
        ReactiveAuthenticationTestConfiguration::class,
        DefaultController::class
    )
    open class Config {

        @Bean(WebHttpHandlerBuilder.WEB_SESSION_MANAGER_BEAN_NAME)
        open fun webSessionManager(): DefaultWebSessionManager {
            return DefaultWebSessionManager()
        }

        @Bean
        open fun reactiveSessionRegistry(): ReactiveSessionRegistry {
            return InMemoryReactiveSessionRegistry()
        }

    }

    @RestController
    open class DefaultController {

        @GetMapping("/")
        fun index(): String {
            return "ok"
        }

    }


}
