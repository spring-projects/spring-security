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

package org.springframework.security.config.annotation.web

import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.RSAKey
import com.nimbusds.jose.jwk.source.ImmutableJWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.interfaces.RSAPublicKey
import java.util.UUID

/**
 * Tests for [OAuth2AuthorizationServerDsl]
 *
 * @author Mehrdad
 */
@ExtendWith(SpringTestContextExtension::class)
class OAuth2AuthorizationServerDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `oauth2AuthorizationServer when custom registered client repository then configuration applies`() {
        this.spring.register(AuthorizationServerConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                }
            }
            return http.build()
        }

        @Bean
        open fun registeredClientRepository(): RegisteredClientRepository {
            val registeredClient = RegisteredClient.withId("test-client")
                .clientId("test-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }
    }

    @Test
    fun `oauth2AuthorizationServer when oidc configured then oidc enabled`() {
        this.spring.register(AuthorizationServerOidcConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerOidcConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    oidc {
                        // Enable OIDC support
                    }
                }
            }
            return http.build()
        }

        @Bean
        open fun registeredClientRepository(): RegisteredClientRepository {
            val registeredClient = RegisteredClient.withId("test-client")
                .clientId("test-client")
                .clientSecret("{noop}secret")
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://localhost:8080/authorized")
                .scope("openid")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        @Bean
        open fun jwkSource(): JWKSource<SecurityContext> {
            val keyPair = generateRsaKey()
            val rsaKey = RSAKey.Builder(keyPair.public as RSAPublicKey)
                .privateKey(keyPair.private)
                .keyID(UUID.randomUUID().toString())
                .build()
            val jwkSet = JWKSet(rsaKey)
            return ImmutableJWKSet(jwkSet)
        }

        @Bean
        open fun jwtDecoder(jwkSource: JWKSource<SecurityContext>): JwtDecoder {
            return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource)
        }

        private fun generateRsaKey(): KeyPair {
            val keyPairGenerator = KeyPairGenerator.getInstance("RSA")
            keyPairGenerator.initialize(2048)
            return keyPairGenerator.generateKeyPair()
        }
    }
}

