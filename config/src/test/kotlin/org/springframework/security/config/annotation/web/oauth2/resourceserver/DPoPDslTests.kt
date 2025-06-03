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

package org.springframework.security.config.annotation.web.oauth2.resourceserver

import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.jwk.JWK
import com.nimbusds.jose.jwk.JWKSelector
import com.nimbusds.jose.jwk.JWKSet
import com.nimbusds.jose.jwk.source.JWKSource
import com.nimbusds.jose.proc.SecurityContext
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpHeaders
import org.springframework.http.HttpMethod
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames
import org.springframework.security.oauth2.jose.TestJwks
import org.springframework.security.oauth2.jose.TestKeys
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm
import org.springframework.security.oauth2.jwt.*
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RequestMethod
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.servlet.config.annotation.EnableWebMvc
import java.nio.charset.StandardCharsets
import java.security.MessageDigest
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.interfaces.RSAPrivateKey
import java.security.interfaces.RSAPublicKey
import java.time.Instant
import java.time.temporal.ChronoUnit
import java.util.*

/**
 * Tests for [DPoPDsl]
 *
 * @author Max Batischev
 */
class DPoPDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun requestWhenDPoPAndBearerAuthenticationThenUnauthorized() {
        spring.register(SecurityConfig::class.java, ResourceEndpoints::class.java).autowire()
        val scope = setOf("resource1.read")
        val accessToken = generateAccessToken(scope, CLIENT_EC_KEY)
        val dPoPProof = generateDPoPProof(HttpMethod.GET.name(), "http://localhost/resource1", accessToken)
        // @formatter:off
        this.mockMvc.perform(MockMvcRequestBuilders.get("/resource1")
                .header(HttpHeaders.AUTHORIZATION, "DPoP $accessToken")
                .header(HttpHeaders.AUTHORIZATION, "Bearer $accessToken")
                .header("DPoP", dPoPProof))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.header().string(HttpHeaders.WWW_AUTHENTICATE,
                        "DPoP error=\"invalid_request\", error_description=\"Found multiple Authorization headers.\", algs=\"RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512\""))
        // @formatter:on
    }

    @Test
    fun requestWhenDPoPAccessTokenMalformedThenUnauthorized() {
        spring.register(SecurityConfig::class.java, ResourceEndpoints::class.java).autowire()
        val scope = setOf("resource1.read")
        val accessToken = generateAccessToken(scope, CLIENT_EC_KEY)
        val dPoPProof = generateDPoPProof(HttpMethod.GET.name(), "http://localhost/resource1", accessToken)
        // @formatter:off
        this.mockMvc.perform(MockMvcRequestBuilders.get("/resource1")
                .header(HttpHeaders.AUTHORIZATION, "DPoP $accessToken m a l f o r m e d ")
                .header("DPoP", dPoPProof))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.header().string(HttpHeaders.WWW_AUTHENTICATE,
                        "DPoP error=\"invalid_token\", error_description=\"DPoP access token is malformed.\", algs=\"RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512\""))
        // @formatter:on
    }

    @Test
    fun requestWhenMultipleDPoPProofsThenUnauthorized() {
        spring.register(SecurityConfig::class.java, ResourceEndpoints::class.java).autowire()
        val scope = setOf("resource1.read")
        val accessToken = generateAccessToken(scope, CLIENT_EC_KEY)
        val dPoPProof = generateDPoPProof(HttpMethod.GET.name(), "http://localhost/resource1", accessToken)
        // @formatter:off
        this.mockMvc.perform(MockMvcRequestBuilders.get("/resource1")
                .header(HttpHeaders.AUTHORIZATION, "DPoP $accessToken")
                .header("DPoP", dPoPProof)
                .header("DPoP", dPoPProof))
                .andExpect(MockMvcResultMatchers.status().isUnauthorized())
                .andExpect(MockMvcResultMatchers.header().string(HttpHeaders.WWW_AUTHENTICATE,
                        "DPoP error=\"invalid_request\", error_description=\"DPoP proof is missing or invalid.\", algs=\"RS256 RS384 RS512 PS256 PS384 PS512 ES256 ES384 ES512\""))
        // @formatter:on
    }

    @Test
    fun requestWhenDPoPAuthenticationValidThenAccessed() {
        spring.register(SecurityConfig::class.java, ResourceEndpoints::class.java).autowire()
        val scope = setOf("resource1.read")
        val accessToken = generateAccessToken(scope, CLIENT_EC_KEY)
        val dPoPProof = generateDPoPProof(HttpMethod.GET.name(), "http://localhost/resource1", accessToken)
        // @formatter:off
        this.mockMvc.perform(MockMvcRequestBuilders.get("/resource1")
                .header(HttpHeaders.AUTHORIZATION, "DPoP $accessToken")
                .header("DPoP", dPoPProof))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.content().string("resource1"))
        // @formatter:on
    }

    private fun generateAccessToken(scope: Set<String>, jwk: JWK?): String {
        var jktClaim: MutableMap<String?, Any?>? = null
        if (jwk != null) {
            try {
                val sha256Thumbprint = jwk.toPublicJWK().computeThumbprint().toString()
                jktClaim = HashMap()
                jktClaim["jkt"] = sha256Thumbprint
            } catch (ignored: java.lang.Exception) {
            }
        }
        val jwsHeader = JwsHeader.with(SignatureAlgorithm.RS256).build()
        val issuedAt = Instant.now()
        val expiresAt = issuedAt.plus(30, ChronoUnit.MINUTES)
        // @formatter:off
        val claimsBuilder = JwtClaimsSet.builder()
                .issuer("https://provider.com")
                .subject("subject")
                .issuedAt(issuedAt)
                .expiresAt(expiresAt)
                .id(UUID.randomUUID().toString())
                .claim(OAuth2ParameterNames.SCOPE, scope)
        if (jktClaim != null) {
            claimsBuilder.claim("cnf", jktClaim) // Bind client public key
        }
        // @formatter:on
        val jwt = providerJwtEncoder!!.encode(JwtEncoderParameters.from(jwsHeader, claimsBuilder.build()))
        return jwt.tokenValue
    }

    private fun generateDPoPProof(method: String, resourceUri: String, accessToken: String): String {
        // @formatter:off
        val publicJwk = CLIENT_EC_KEY.toPublicJWK().toJSONObject()
        val jwsHeader = JwsHeader.with(SignatureAlgorithm.ES256)
                .type("dpop+jwt")
                .jwk(publicJwk)
                .build()
        val claims = JwtClaimsSet.builder()
                .issuedAt(Instant.now())
                .claim("htm", method)
                .claim("htu", resourceUri)
                .claim("ath", computeSHA256(accessToken))
                .id(UUID.randomUUID().toString())
                .build()
        // @formatter:on
        val jwt = clientJwtEncoder!!.encode(JwtEncoderParameters.from(jwsHeader, claims))
        return jwt.tokenValue
    }

    private fun computeSHA256(value: String): String {
        val md = MessageDigest.getInstance("SHA-256")
        val digest = md.digest(value.toByteArray(StandardCharsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    internal open class SecurityConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/resource1", hasAnyAuthority("SCOPE_resource1.read", "SCOPE_resource1.write"))
                    authorize("/resource2", hasAnyAuthority("SCOPE_resource2.read", "SCOPE_resource2.write"))
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    jwt { }
                    dpop { }
                }
            }
            return http.build()
        }

        @Bean
        open fun jwtDecoder(): NimbusJwtDecoder = NimbusJwtDecoder.withPublicKey(PROVIDER_RSA_PUBLIC_KEY).build()

    }

    @RestController
    internal class ResourceEndpoints {
        @RequestMapping(value = ["/resource1"], method = [RequestMethod.GET, RequestMethod.POST])
        fun resource1(): String {
            return "resource1"
        }

        @RequestMapping(value = ["/resource2"], method = [RequestMethod.GET, RequestMethod.POST])
        fun resource2(): String {
            return "resource2"
        }
    }

    companion object {
        private val PROVIDER_RSA_PUBLIC_KEY: RSAPublicKey = TestKeys.DEFAULT_PUBLIC_KEY

        private val PROVIDER_RSA_PRIVATE_KEY: RSAPrivateKey = TestKeys.DEFAULT_PRIVATE_KEY

        private val CLIENT_EC_PUBLIC_KEY = TestKeys.DEFAULT_EC_KEY_PAIR.public as ECPublicKey

        private val CLIENT_EC_PRIVATE_KEY = TestKeys.DEFAULT_EC_KEY_PAIR.private as ECPrivateKey

        private val CLIENT_EC_KEY: ECKey = TestJwks.jwk(CLIENT_EC_PUBLIC_KEY, CLIENT_EC_PRIVATE_KEY).build()

        private var providerJwtEncoder: NimbusJwtEncoder? = null

        private var clientJwtEncoder: NimbusJwtEncoder? = null

        @JvmStatic
        @BeforeAll
        fun init() {
            val providerRsaKey = TestJwks.jwk(PROVIDER_RSA_PUBLIC_KEY, PROVIDER_RSA_PRIVATE_KEY).build()
            val providerJwkSource = JWKSource { jwkSelector: JWKSelector, _: SecurityContext? ->
                jwkSelector
                        .select(JWKSet(providerRsaKey))
            }
            providerJwtEncoder = NimbusJwtEncoder(providerJwkSource)
            val clientJwkSource = JWKSource { jwkSelector: JWKSelector, securityContext: SecurityContext? ->
                jwkSelector
                        .select(JWKSet(CLIENT_EC_KEY))
            }
            clientJwtEncoder = NimbusJwtEncoder(clientJwkSource)
        }
    }
}
