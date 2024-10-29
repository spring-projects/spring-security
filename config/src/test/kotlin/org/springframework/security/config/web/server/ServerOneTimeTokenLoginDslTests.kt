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

import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import reactor.core.publisher.Mono

import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.context.annotation.Import
import org.springframework.context.ApplicationContext
import org.springframework.http.MediaType
import org.springframework.security.authentication.ott.OneTimeToken
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.userdetails.MapReactiveUserDetailsService
import org.springframework.security.core.userdetails.ReactiveUserDetailsService
import org.springframework.security.core.userdetails.User
import org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.RedirectServerAuthenticationSuccessHandler
import org.springframework.security.web.server.authentication.ott.ServerOneTimeTokenGenerationSuccessHandler
import org.springframework.security.web.server.authentication.ott.ServerRedirectOneTimeTokenGenerationSuccessHandler
import org.springframework.test.web.reactive.server.WebTestClient
import org.springframework.web.reactive.config.EnableWebFlux
import org.springframework.web.reactive.function.BodyInserters
import org.springframework.web.server.ServerWebExchange
import org.springframework.web.util.UriBuilder

/**
 * Tests for [ServerOneTimeTokenLoginDsl]
 *
 * @author Max Batischev
 */
@ExtendWith(SpringTestContextExtension::class)
class ServerOneTimeTokenLoginDslTests {
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
    fun `oneTimeToken when correct token then can authenticate`() {
        spring.register(OneTimeTokenConfig::class.java).autowire()

        // @formatter:off
        client.mutateWith(SecurityMockServerConfigurers.csrf())
            .post()
            .uri{ uriBuilder: UriBuilder -> uriBuilder
                .path("/ott/generate")
                .build()
            }
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData("username", "user"))
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .expectHeader().valueEquals("Location", "/login/ott")

        client.mutateWith(SecurityMockServerConfigurers.csrf())
            .post()
            .uri{ uriBuilder:UriBuilder -> uriBuilder
                .path("/ott/generate")
                .build()
            }
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData("username", "user"))
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .expectHeader().valueEquals("Location", "/login/ott")

        val token = TestServerOneTimeTokenGenerationSuccessHandler.lastToken?.tokenValue

        client.mutateWith(SecurityMockServerConfigurers.csrf())
            .post()
            .uri{ uriBuilder:UriBuilder -> uriBuilder
                .path("/login/ott")
                .queryParam("token", token)
                .build()
            }
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .expectHeader().valueEquals("Location", "/")
        // @formatter:on
    }

    @Test
    fun `oneTimeToken when different authentication urls then can authenticate`() {
        spring.register(OneTimeTokenDifferentUrlsConfig::class.java).autowire()

        // @formatter:off
        client.mutateWith(SecurityMockServerConfigurers.csrf())
            .post()
            .uri{ uriBuilder: UriBuilder -> uriBuilder
                .path("/generateurl")
                .build()
            }
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData("username", "user"))
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .expectHeader().valueEquals("Location", "/redirected")

        val token = TestServerOneTimeTokenGenerationSuccessHandler.lastToken?.tokenValue

        client.mutateWith(SecurityMockServerConfigurers.csrf())
            .post()
            .uri{ uriBuilder: UriBuilder -> uriBuilder
                .path("/loginprocessingurl")
                .build()
            }
            .contentType(MediaType.APPLICATION_FORM_URLENCODED)
            .body(BodyInserters.fromFormData("token", token!!))
            .exchange()
            .expectStatus()
            .is3xxRedirection()
            .expectHeader().valueEquals("Location", "/authenticated")
        // @formatter:on
    }

    @Configuration
    @EnableWebFlux
    @EnableWebFluxSecurity
    @Import(UserDetailsServiceConfig::class)
    open class OneTimeTokenConfig {

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            // @formatter:off
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oneTimeTokenLogin {
                    tokenGenerationSuccessHandler = TestServerOneTimeTokenGenerationSuccessHandler()
                }
            }
            // @formatter:on
        }
    }

    @Configuration
    @EnableWebFlux
    @EnableWebFluxSecurity
    @Import(UserDetailsServiceConfig::class)
    open class OneTimeTokenDifferentUrlsConfig {

        @Bean
        open fun springWebFilterChain(http: ServerHttpSecurity): SecurityWebFilterChain {
            // @formatter:off
            return http {
                authorizeExchange {
                    authorize(anyExchange, authenticated)
                }
                oneTimeTokenLogin {
                    tokenGeneratingUrl = "/generateurl"
                    tokenGenerationSuccessHandler = TestServerOneTimeTokenGenerationSuccessHandler("/redirected")
                    loginProcessingUrl = "/loginprocessingurl"
                    authenticationSuccessHandler = RedirectServerAuthenticationSuccessHandler("/authenticated")
                }
            }
            // @formatter:on
        }
    }

    @Configuration(proxyBeanMethods = false)
    open class UserDetailsServiceConfig {

        @Bean
        open fun userDetailsService(): ReactiveUserDetailsService =
            MapReactiveUserDetailsService(User("user", "password", listOf()))
    }

    private class TestServerOneTimeTokenGenerationSuccessHandler: ServerOneTimeTokenGenerationSuccessHandler {
        private var delegate: ServerRedirectOneTimeTokenGenerationSuccessHandler? = null

        companion object {
            var lastToken: OneTimeToken? = null
        }

        constructor() {
            this.delegate = ServerRedirectOneTimeTokenGenerationSuccessHandler("/login/ott")
        }

        constructor(redirectUrl: String?) {
            this.delegate = ServerRedirectOneTimeTokenGenerationSuccessHandler(redirectUrl)
        }

        override fun handle(exchange: ServerWebExchange?, oneTimeToken: OneTimeToken?): Mono<Void> {
            lastToken = oneTimeToken
            return delegate!!.handle(exchange, oneTimeToken)
        }
    }
}
