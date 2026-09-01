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

package org.springframework.security.config.annotation.web.oauth2.resourceserver

import org.hamcrest.Matchers.hasItem
import org.hamcrest.Matchers.hasSize
import org.junit.jupiter.api.Test
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.oauth2.jose.TestKeys
import org.springframework.security.oauth2.jwt.JwtDecoder
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadataClaimNames
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers

/**
 * Tests for [ProtectedResourceMetadataDsl].
 *
 * @author Andrey Litvitski
 */
class ProtectedResourceMetadataDslTests {

    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun requestWhenProtectedResourceMetadataRequestThenReturnMetadataResponse() {
        this.spring.register(ResourceServerConfiguration::class.java).autowire()
        this.mockMvc.perform(
            MockMvcRequestBuilders.get(RESOURCE + DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI)
        )
            .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE).value(RESOURCE))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED).isArray())
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED).value(hasSize<Any>(1)))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED).value(hasItem("header")))
            .andExpect(
                MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS)
                    .value(true)
            )
            .andReturn()
    }

    @Test
    fun requestWhenProtectedResourceMetadataRequestIncludesResourcePathThenMetadataResponseHasResourcePath() {
        this.spring.register(ResourceServerConfiguration::class.java).autowire()
        val host = RESOURCE
        var resourcePath = "/resource1"
        var resource = host + resourcePath
        this.mockMvc.perform(
            MockMvcRequestBuilders.get(host + DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI + resourcePath)
        )
            .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE).value(resource))
            .andReturn()
        resourcePath = "/path1/resource2"
        resource = host + resourcePath
        this.mockMvc.perform(
            MockMvcRequestBuilders.get(host + DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI + resourcePath)
        )
            .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE).value(resource))
            .andReturn()
        resourcePath = "/path1/path2/resource3"
        resource = host + resourcePath
        this.mockMvc.perform(
            MockMvcRequestBuilders.get(host + DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI + resourcePath)
        )
            .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE).value(resource))
            .andReturn()
    }

    @Test
    fun requestWhenProtectedResourceMetadataRequestAndMetadataCustomizerSetThenReturnCustomMetadataResponse() {
        this.spring.register(ResourceServerConfigurationWithMetadataCustomizer::class.java).autowire()
        this.mockMvc.perform(
            MockMvcRequestBuilders.get(RESOURCE + DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI)
        )
            .andExpect(MockMvcResultMatchers.status().is2xxSuccessful())
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE).value(RESOURCE))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS).isArray())
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS).value(hasSize<Any>(2)))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS).value(hasItem(ISSUER_1)))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.AUTHORIZATION_SERVERS).value(hasItem(ISSUER_2)))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED).isArray())
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED).value(hasSize<Any>(2)))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED).value(hasItem("scope1")))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.SCOPES_SUPPORTED).value(hasItem("scope2")))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED).isArray())
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED).value(hasSize<Any>(1)))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.BEARER_METHODS_SUPPORTED).value(hasItem("header")))
            .andExpect(MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.RESOURCE_NAME).value("resourceName"))
            .andExpect(
                MockMvcResultMatchers.jsonPath(OAuth2ProtectedResourceMetadataClaimNames.TLS_CLIENT_CERTIFICATE_BOUND_ACCESS_TOKENS)
                    .value(true)
            )
            .andReturn()
    }

    @EnableWebSecurity
    @Configuration(proxyBeanMethods = false)
    internal open class ResourceServerConfiguration {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    jwt { }
                }
            }
            return http.build()
        }

        @Bean
        open fun jwtDecoder(): JwtDecoder {
            return NimbusJwtDecoder.withPublicKey(TestKeys.DEFAULT_PUBLIC_KEY).build()
        }

    }

    @EnableWebSecurity
    @Configuration(proxyBeanMethods = false)
    internal open class ResourceServerConfigurationWithMetadataCustomizer : ResourceServerConfiguration() {

        @Bean
        override fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(anyRequest, authenticated)
                }
                oauth2ResourceServer {
                    jwt { }
                    protectedResourceMetadata {
                        protectedResourceMetadataCustomizer { protectedResourceMetadata ->
                            protectedResourceMetadata.authorizationServer(ISSUER_1)
                                .authorizationServer(ISSUER_2)
                                .scope("scope1")
                                .scope("scope2")
                                .resourceName("resourceName")
                        }
                    }
                }
            }
            return http.build()
        }

    }

    companion object {

        private const val DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI =
            "/.well-known/oauth-protected-resource"

        private const val RESOURCE = "https://resource.com:8443"

        private const val ISSUER_1 = "https://provider1.com"

        private const val ISSUER_2 = "https://provider2.com"

    }

}
