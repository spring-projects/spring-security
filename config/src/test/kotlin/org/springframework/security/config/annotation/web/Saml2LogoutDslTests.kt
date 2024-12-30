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

package org.springframework.security.config.annotation.web

import org.assertj.core.api.Assertions
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.BeanCreationException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.TestAuthentication
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors
import org.springframework.security.web.SecurityFilterChain
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.MvcResult
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders
import org.springframework.test.web.servlet.result.MockMvcResultMatchers
import java.util.*

/**
 * Tests for [Saml2LogoutDsl]
 *
 * @author Josh Cummings
 */
@ExtendWith(SpringTestContextExtension::class)
class Saml2LogoutDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `saml2Logout when no relying party registration repository then exception`() {
        Assertions.assertThatThrownBy { this.spring.register(Saml2LogoutNoRelyingPartyRegistrationRepoConfig::class.java).autowire() }
                .isInstanceOf(BeanCreationException::class.java)
                .hasMessageContaining("relyingPartyRegistrationRepository cannot be null")

    }

    @Test
    @Throws(Exception::class)
    fun `saml2Logout when defaults and not saml login then default logout`() {
        this.spring.register(Saml2LogoutDefaultsConfig::class.java).autowire()
        val user = TestAuthentication.authenticatedUser()
        val result: MvcResult = this.mockMvc.perform(
            MockMvcRequestBuilders.post("/logout").with(SecurityMockMvcRequestPostProcessors.authentication(user))
                .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(MockMvcResultMatchers.status().isFound())
            .andReturn()
        val location = result.response.getHeader("Location")
        Assertions.assertThat(location).isEqualTo("/login?logout")
    }

    @Test
    @Throws(Exception::class)
    fun saml2LogoutWhenDefaultsThenLogsOutAndSendsLogoutRequest() {
        this.spring.register(Saml2LogoutDefaultsConfig::class.java).autowire()
        val principal = DefaultSaml2AuthenticatedPrincipal("user", emptyMap())
        principal.relyingPartyRegistrationId = "registration-id"
        val user = Saml2Authentication(principal, "response", AuthorityUtils.createAuthorityList("ROLE_USER"))
        val result: MvcResult = this.mockMvc.perform(MockMvcRequestBuilders.post("/logout")
            .with(SecurityMockMvcRequestPostProcessors.authentication(user))
            .with(SecurityMockMvcRequestPostProcessors.csrf()))
            .andExpect(MockMvcResultMatchers.status().isFound())
            .andReturn()
        val location = result.response.getHeader("Location")
        Assertions.assertThat(location).startsWith("https://ap.example.org/logout/saml2/request")
    }

    @Configuration
    @EnableWebSecurity
    open class Saml2LogoutNoRelyingPartyRegistrationRepoConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                saml2Logout { }
            }
            return http.build()
        }
    }

    @Configuration
    @EnableWebSecurity
    open class Saml2LogoutDefaultsConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                saml2Logout { }
            }
            return http.build()
        }

        @Bean
        open fun registrations(): RelyingPartyRegistrationRepository =
            InMemoryRelyingPartyRegistrationRepository(TestRelyingPartyRegistrations.full().build())

    }

}
