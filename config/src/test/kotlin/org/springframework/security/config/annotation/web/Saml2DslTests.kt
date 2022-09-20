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
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations
import org.springframework.security.saml2.provider.service.web.authentication.Saml2WebSsoAuthenticationFilter
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import java.security.cert.Certificate
import java.security.cert.CertificateFactory
import java.util.Base64

/**
 * Tests for [Saml2Dsl]
 *
 * @author Eleftheria Stein
 */
@ExtendWith(SpringTestContextExtension::class)
class Saml2DslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `saml2Login when no relying party registration repository then exception`() {
        Assertions.assertThatThrownBy { this.spring.register(Saml2LoginNoRelyingPArtyRegistrationRepoConfig::class.java).autowire() }
                .isInstanceOf(BeanCreationException::class.java)
                .hasMessageContaining("relyingPartyRegistrationRepository cannot be null")

    }

    @Configuration
    @EnableWebSecurity
    open class Saml2LoginNoRelyingPArtyRegistrationRepoConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                saml2Login { }
            }
            return http.build()
        }
    }

    @Test
    fun `login page when saml2Configured then default login page created`() {
        this.spring.register(Saml2LoginConfig::class.java).autowire()

        this.mockMvc.get("/login")
                .andExpect {
                    status { isOk() }
                }
    }

    @Configuration
    @EnableWebSecurity
    open class Saml2LoginConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                saml2Login {
                    relyingPartyRegistrationRepository =
                            InMemoryRelyingPartyRegistrationRepository(
                                    RelyingPartyRegistration.withRegistrationId("samlId")
                                            .assertionConsumerServiceLocation("{baseUrl}" + Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI)
                                            .assertingPartyDetails { a -> a
                                                .verificationX509Credentials { c -> c
                                                    .add(Saml2X509Credential(loadCert("rod.cer"), Saml2X509Credential.Saml2X509CredentialType.VERIFICATION))
                                                }
                                            }
                                            .assertingPartyDetails { c -> c.singleSignOnServiceLocation("ssoUrl") }
                                            .assertingPartyDetails { c -> c.entityId("entityId") }
                                            .build()
                            )
                }
            }
            return http.build()
        }

        private fun <T : Certificate> loadCert(location: String): T {
            ClassPathResource(location).inputStream.use { inputStream ->
                val certFactory = CertificateFactory.getInstance("X.509")
                return certFactory.generateCertificate(inputStream) as T
            }
        }
    }

    @Test
    fun `authenticate when custom AuthenticationManager then used`() {
        this.spring.register(Saml2LoginCustomAuthenticationManagerConfig::class.java).autowire()
        mockkObject(Saml2LoginCustomAuthenticationManagerConfig.AUTHENTICATION_MANAGER)
        val  request = MockMvcRequestBuilders.post("/login/saml2/sso/id")
            .param("SAMLResponse", Base64.getEncoder().encodeToString("saml2-xml-response-object".toByteArray()))
        this.mockMvc.perform(request)
        verify(exactly = 1) { Saml2LoginCustomAuthenticationManagerConfig.AUTHENTICATION_MANAGER.authenticate(any()) }
    }

    @Configuration
    @EnableWebSecurity
    open class Saml2LoginCustomAuthenticationManagerConfig {
        companion object {
            val AUTHENTICATION_MANAGER: AuthenticationManager = ProviderManager(TestingAuthenticationProvider())
        }

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                saml2Login {
                    authenticationManager = AUTHENTICATION_MANAGER
                }
            }
            return http.build()
        }

        @Bean
        open fun relyingPartyRegistrationRepository(): RelyingPartyRegistrationRepository? {
            val repository: RelyingPartyRegistrationRepository = mockk()
            every {
                repository.findByRegistrationId(any())
            } returns TestRelyingPartyRegistrations.relyingPartyRegistration().build()
            return repository
        }
    }
}
