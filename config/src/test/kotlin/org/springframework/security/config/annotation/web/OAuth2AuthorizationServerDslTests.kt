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
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.Authentication
import org.springframework.security.oauth2.core.AuthorizationGrantType
import org.springframework.security.oauth2.core.ClientAuthenticationMethod
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository
import org.springframework.security.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.test.web.servlet.MockMvc
import jakarta.servlet.ServletException
import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import java.io.IOException
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

    @Test
    fun `oauth2AuthorizationServer when authorizationEndpoint configured with authorizationRequestConverter then configuration applies`() {
        this.spring.register(AuthorizationServerWithAuthorizationEndpointConverterConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithAuthorizationEndpointConverterConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    authorizationEndpoint {
                        authorizationRequestConverter = customAuthorizationRequestConverter()
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAuthorizationRequestConverter(): AuthenticationConverter {
            return AuthenticationConverter { request ->
                null
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when authorizationEndpoint configured with authorizationRequestConverters then configuration applies`() {
        this.spring.register(AuthorizationServerWithAuthorizationEndpointConvertersConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithAuthorizationEndpointConvertersConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    authorizationEndpoint {
                        authorizationRequestConverters = java.util.function.Consumer { converters ->
                            converters.add(customAuthorizationRequestConverter())
                        }
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAuthorizationRequestConverter(): AuthenticationConverter {
            return AuthenticationConverter { request ->
                null
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when authorizationEndpoint configured with authenticationProvider then configuration applies`() {
        this.spring.register(AuthorizationServerWithAuthorizationEndpointProviderConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithAuthorizationEndpointProviderConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    authorizationEndpoint {
                        authenticationProvider = customAuthenticationProvider()
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAuthenticationProvider(): AuthenticationProvider {
            return object : AuthenticationProvider {
                override fun authenticate(authentication: Authentication): Authentication? {
                    return null
                }

                override fun supports(authentication: Class<*>): Boolean {
                    return false
                }
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when authorizationEndpoint configured with authenticationProviders then configuration applies`() {
        this.spring.register(AuthorizationServerWithAuthorizationEndpointProvidersConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithAuthorizationEndpointProvidersConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    authorizationEndpoint {
                        authenticationProviders = java.util.function.Consumer { providers ->
                            providers.add(customAuthenticationProvider())
                        }
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAuthenticationProvider(): AuthenticationProvider {
            return object : AuthenticationProvider {
                override fun authenticate(authentication: Authentication): Authentication? {
                    return null
                }

                override fun supports(authentication: Class<*>): Boolean {
                    return false
                }
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when authorizationEndpoint configured with successResponseHandler then configuration applies`() {
        this.spring.register(AuthorizationServerWithAuthorizationEndpointResponseHandlerConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithAuthorizationEndpointResponseHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    authorizationEndpoint {
                        authorizationResponseHandler = customSuccessHandler()
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customSuccessHandler(): AuthenticationSuccessHandler {
            return AuthenticationSuccessHandler { request, response, authentication ->
                // Custom success handling
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when authorizationEndpoint configured with errorResponseHandler then configuration applies`() {
        this.spring.register(AuthorizationServerWithAuthorizationEndpointErrorHandlerConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithAuthorizationEndpointErrorHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    authorizationEndpoint {
                        errorResponseHandler = customErrorHandler()
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customErrorHandler(): AuthenticationFailureHandler {
            return AuthenticationFailureHandler { request, response, exception ->
                // Custom error handling
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when tokenEndpoint configured with accessTokenRequestConverter then configuration applies`() {
        this.spring.register(AuthorizationServerWithTokenEndpointConverterConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithTokenEndpointConverterConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    tokenEndpoint {
                        accessTokenRequestConverter = customAccessTokenRequestConverter()
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAccessTokenRequestConverter(): AuthenticationConverter {
            return AuthenticationConverter { request ->
                null
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when tokenEndpoint configured with accessTokenRequestConverters then configuration applies`() {
        this.spring.register(AuthorizationServerWithTokenEndpointConvertersConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithTokenEndpointConvertersConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    tokenEndpoint {
                        accessTokenRequestConverters = java.util.function.Consumer { converters ->
                            converters.add(customAccessTokenRequestConverter())
                        }
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
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAccessTokenRequestConverter(): AuthenticationConverter {
            return AuthenticationConverter { request ->
                null
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when tokenEndpoint configured with authenticationProvider then configuration applies`() {
        this.spring.register(AuthorizationServerWithTokenEndpointProviderConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithTokenEndpointProviderConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    tokenEndpoint {
                        authenticationProvider = customAuthenticationProvider()
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
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAuthenticationProvider(): AuthenticationProvider {
            return object : AuthenticationProvider {
                override fun authenticate(authentication: Authentication): Authentication? {
                    return null
                }

                override fun supports(authentication: Class<*>): Boolean {
                    return false
                }
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when tokenEndpoint configured with authenticationProviders then configuration applies`() {
        this.spring.register(AuthorizationServerWithTokenEndpointProvidersConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithTokenEndpointProvidersConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    tokenEndpoint {
                        authenticationProviders = java.util.function.Consumer { providers ->
                            providers.add(customAuthenticationProvider())
                        }
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
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAuthenticationProvider(): AuthenticationProvider {
            return object : AuthenticationProvider {
                override fun authenticate(authentication: Authentication): Authentication? {
                    return null
                }

                override fun supports(authentication: Class<*>): Boolean {
                    return false
                }
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when tokenEndpoint configured with successResponseHandler then configuration applies`() {
        this.spring.register(AuthorizationServerWithTokenEndpointResponseHandlerConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithTokenEndpointResponseHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    tokenEndpoint {
                        accessTokenResponseHandler = customSuccessHandler()
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
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customSuccessHandler(): AuthenticationSuccessHandler {
            return AuthenticationSuccessHandler { request, response, authentication ->
                // Custom success handling
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when tokenEndpoint configured with errorResponseHandler then configuration applies`() {
        this.spring.register(AuthorizationServerWithTokenEndpointErrorHandlerConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithTokenEndpointErrorHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    tokenEndpoint {
                        errorResponseHandler = customErrorHandler()
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
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customErrorHandler(): AuthenticationFailureHandler {
            return AuthenticationFailureHandler { request, response, exception ->
                // Custom error handling
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when clientAuthentication configured with authenticationConverter then configuration applies`() {
        this.spring.register(AuthorizationServerWithClientAuthenticationConverterConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithClientAuthenticationConverterConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    clientAuthentication {
                        authenticationConverter = customAuthenticationConverter()
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAuthenticationConverter(): AuthenticationConverter {
            return AuthenticationConverter { request ->
                null
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when clientAuthentication configured with authenticationConverters then configuration applies`() {
        this.spring.register(AuthorizationServerWithClientAuthenticationConvertersConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithClientAuthenticationConvertersConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    clientAuthentication {
                        authenticationConverters = java.util.function.Consumer { converters ->
                            converters.add(customAuthenticationConverter())
                        }
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAuthenticationConverter(): AuthenticationConverter {
            return AuthenticationConverter { request ->
                null
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when clientAuthentication configured with authenticationProvider then configuration applies`() {
        this.spring.register(AuthorizationServerWithClientAuthenticationProviderConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithClientAuthenticationProviderConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    clientAuthentication {
                        authenticationProvider = customAuthenticationProvider()
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAuthenticationProvider(): AuthenticationProvider {
            return object : AuthenticationProvider {
                override fun authenticate(authentication: Authentication): Authentication? {
                    return null
                }

                override fun supports(authentication: Class<*>): Boolean {
                    return false
                }
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when clientAuthentication configured with authenticationProviders then configuration applies`() {
        this.spring.register(AuthorizationServerWithClientAuthenticationProvidersConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithClientAuthenticationProvidersConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    clientAuthentication {
                        authenticationProviders = java.util.function.Consumer { providers ->
                            providers.add(customAuthenticationProvider())
                        }
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customAuthenticationProvider(): AuthenticationProvider {
            return object : AuthenticationProvider {
                override fun authenticate(authentication: Authentication): Authentication? {
                    return null
                }

                override fun supports(authentication: Class<*>): Boolean {
                    return false
                }
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when clientAuthentication configured with successHandler then configuration applies`() {
        this.spring.register(AuthorizationServerWithClientAuthenticationSuccessHandlerConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithClientAuthenticationSuccessHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    clientAuthentication {
                        authenticationSuccessHandler = customSuccessHandler()
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customSuccessHandler(): AuthenticationSuccessHandler {
            return AuthenticationSuccessHandler { request, response, authentication ->
                // Custom success handling
            }
        }
    }

    @Test
    fun `oauth2AuthorizationServer when clientAuthentication configured with errorResponseHandler then configuration applies`() {
        this.spring.register(AuthorizationServerWithClientAuthenticationErrorHandlerConfig::class.java).autowire()
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizationServerWithClientAuthenticationErrorHandlerConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                oauth2AuthorizationServer {
                    registeredClientRepository = registeredClientRepository()
                    clientAuthentication {
                        errorResponseHandler = customErrorHandler()
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
                .redirectUri("http://localhost:8080/authorized")
                .build()
            return InMemoryRegisteredClientRepository(registeredClient)
        }

        @Bean
        open fun authorizationServerSettings(): AuthorizationServerSettings {
            return AuthorizationServerSettings.builder().build()
        }

        private fun customErrorHandler(): AuthenticationFailureHandler {
            return AuthenticationFailureHandler { request, response, exception ->
                // Custom error handling
            }
        }
    }
}


