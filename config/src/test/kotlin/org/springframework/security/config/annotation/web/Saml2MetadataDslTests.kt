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

import io.mockk.every
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.verify
import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.io.ClassPathResource
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.authentication.ProviderManager
import org.springframework.security.authentication.TestingAuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.saml2.core.Saml2X509Credential
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponse
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponseResolver
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.Base64

/**
 * Tests for [Saml2Dsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class Saml2MetadataDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `saml2Metadat when no relying party registration repository then exception`() {
        Assertions.assertThatThrownBy { this.spring.register(Saml2MetadataNoRelyingPartyRegistrationRepoConfig::class.java).autowire() }
                .isInstanceOf(BeanCreationException::class.java)
                .hasMessageContaining("relyingPartyRegistrationRepository cannot be null")

    }

    @Configuration
    @EnableWebSecurity
    open class Saml2MetadataNoRelyingPartyRegistrationRepoConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                saml2Metadata { }
            }
            return http.build()
        }
    }

    @Test
    fun `metadata endpoint when saml2Metadata configured then metadata returned`() {
        this.spring.register(Saml2MetadataConfig::class.java).autowire()

        this.mockMvc.get("/saml2/metadata")
                .andExpect {
                    status { isOk() }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class Saml2MetadataConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                saml2Metadata { }
            }
            return http.build()
        }

		@Bean
		open fun registrations(): RelyingPartyRegistrationRepository {
			return InMemoryRelyingPartyRegistrationRepository(TestRelyingPartyRegistrations.full().build())
		}

        private fun <T : Certificate> loadCert(location: String): T {
            ClassPathResource(location).inputStream.use { inputStream ->
                val certFactory = CertificateFactory.getInstance("X.509")
                return certFactory.generateCertificate(inputStream) as T
            }
        }
    }

    @Test
    fun `metadata endpoint when url customized then used`() {
        this.spring.register(Saml2LoginCustomEndpointConfig::class.java).autowire()
		this.mockMvc.get("/saml/metadata")
			.andExpect {
				status { isOk() }
			}
    }

    @Configuration
    @EnableWebSecurity
    open class Saml2LoginCustomEndpointConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                saml2Metadata {
                    metadataUrl = "/saml/metadata"
                }
            }
            return http.build()
        }

        @Bean
        open fun relyingPartyRegistrationRepository(): RelyingPartyRegistrationRepository? {
			return InMemoryRelyingPartyRegistrationRepository(TestRelyingPartyRegistrations.full().build())
        }
    }

	@Test
	fun `metadata endpoint when resolver customized then used`() {
		this.spring.register(Saml2LoginCustomMetadataResolverConfig::class.java).autowire()
		val mocked = this.spring.context.getBean(Saml2MetadataResponseResolver::class.java)
		every {
			mocked.resolve(any())
		} returns Saml2MetadataResponse("metadata", "file")
		this.mockMvc.get("/saml2/metadata")
			.andExpect {
				status { isOk() }
			}
		verify(exactly = 1) { mocked.resolve(any()) }
	}

	@Configuration
	@EnableWebSecurity
	open class Saml2LoginCustomMetadataResolverConfig {

		private val metadataResponseResolver: Saml2MetadataResponseResolver = mockk()

		@Bean
		open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
			http {
				saml2Metadata {}
			}
			return http.build()
		}

		@Bean
		open fun metadataResponseResolver(): Saml2MetadataResponseResolver? {
			return this.metadataResponseResolver
		}

		@Bean
		open fun relyingPartyRegistrationRepository(): RelyingPartyRegistrationRepository? {
			return InMemoryRelyingPartyRegistrationRepository(TestRelyingPartyRegistrations.full().build())
		}
	}
}
