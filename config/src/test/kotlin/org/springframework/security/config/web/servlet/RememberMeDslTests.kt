/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.config.web.servlet

import io.mockk.Called
import io.mockk.confirmVerified
import io.mockk.every
import io.mockk.justRun
import io.mockk.mockk
import io.mockk.mockkObject
import io.mockk.verify
import javax.servlet.http.HttpServletRequest
import org.assertj.core.api.Assertions.assertThat
import org.junit.Rule
import org.junit.Test
import org.junit.jupiter.api.fail
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.context.annotation.Bean
import org.springframework.core.annotation.Order
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpSession
import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.test.SpringTestRule
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.PasswordEncodedUser
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import org.springframework.security.crypto.password.PasswordEncoder
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.csrf
import org.springframework.security.test.web.servlet.response.SecurityMockMvcResultMatchers
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.authentication.NullRememberMeServices
import org.springframework.security.web.authentication.RememberMeServices
import org.springframework.security.web.authentication.rememberme.AbstractRememberMeServices
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository
import org.springframework.security.web.util.matcher.AntPathRequestMatcher
import org.springframework.test.web.servlet.MockHttpServletRequestDsl
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post

/**
 * Tests for [RememberMeDsl]
 *
 * @author Ivan Pavlov
 */
internal class RememberMeDslTests {

    @Rule
    @JvmField
    val spring = SpringTestRule()

    @Autowired
    lateinit var mockMvc: MockMvc

    private val mockAuthentication: Authentication = mockk()

    @Test
    fun `Remember Me login when remember me true then responds with remember me cookie`() {
        this.spring.register(RememberMeConfig::class.java).autowire()
        mockMvc.post("/login")
        {
            loginRememberMeRequest()
        }.andExpect {
            cookie {
                exists("remember-me")
            }
        }
    }

    @Test
    fun `Remember Me get when remember me cookie then authentication is remember me authentication token`() {
        this.spring.register(RememberMeConfig::class.java).autowire()
        val mvcResult = mockMvc.post("/login")
        {
            loginRememberMeRequest()
        }.andReturn()
        val rememberMeCookie = mvcResult.response.getCookie("remember-me")
                ?: fail { "Missing remember-me cookie in login response" }
        mockMvc.get("/abc")
        {
            cookie(rememberMeCookie)
        }.andExpect {
            val rememberMeAuthentication = SecurityMockMvcResultMatchers.authenticated()
                    .withAuthentication { assertThat(it).isInstanceOf(RememberMeAuthenticationToken::class.java) }
            match(rememberMeAuthentication)
        }
    }

    @Test
    fun `Remember Me logout when remember me cookie then authentication is remember me cookie expired`() {
        this.spring.register(RememberMeConfig::class.java).autowire()
        val mvcResult = mockMvc.post("/login")
        {
            loginRememberMeRequest()
        }.andReturn()
        val rememberMeCookie = mvcResult.response.getCookie("remember-me")
                ?: fail { "Missing remember-me cookie in login response" }
        val mockSession = mvcResult.request.session as MockHttpSession
        mockMvc.post("/logout")
        {
            with(csrf())
            cookie(rememberMeCookie)
            session = mockSession
        }.andExpect {
            status { isFound() }
            redirectedUrl("/login?logout")
            cookie {
                maxAge("remember-me", 0)
            }
        }
    }

    @Test
    fun `Remember Me get when remember me cookie and logged out then redirects to login`() {
        this.spring.register(RememberMeConfig::class.java).autowire()
        mockMvc.perform(formLogin())
        val mvcResult = mockMvc.post("/login")
        {
            loginRememberMeRequest()
        }.andReturn()
        val rememberMeCookie = mvcResult.response.getCookie("remember-me")
                ?: fail { "Missing remember-me cookie in login request" }
        val mockSession = mvcResult.request.session as MockHttpSession
        val logoutMvcResult = mockMvc.post("/logout")
        {
            with(csrf())
            cookie(rememberMeCookie)
            session = mockSession
        }.andReturn()
        val expiredRememberMeCookie = logoutMvcResult.response.getCookie("remember-me")
                ?: fail { "Missing remember-me cookie in logout response" }
        mockMvc.get("/abc")
        {
            with(csrf())
            cookie(expiredRememberMeCookie)
        }.andExpect {
            status { isFound() }
            redirectedUrl("http://localhost/login")
        }
    }

    @Test
    fun `Remember Me login when remember me domain then remember me cookie has domain`() {
        this.spring.register(RememberMeDomainConfig::class.java).autowire()
        mockMvc.post("/login")
        {
            loginRememberMeRequest()
        }.andExpect {
            cookie {
                domain("remember-me", "spring.io")
            }
        }
    }

    @Test
    fun `Remember Me when remember me services then uses`() {
        this.spring.register(RememberMeServicesRefConfig::class.java).autowire()
        mockkObject(RememberMeServicesRefConfig.REMEMBER_ME_SERVICES)
        every {
            RememberMeServicesRefConfig.REMEMBER_ME_SERVICES.autoLogin(any(),any())
        } returns mockAuthentication
        every {
            RememberMeServicesRefConfig.REMEMBER_ME_SERVICES.loginFail(any(), any())
        } returns Unit
        every {
            RememberMeServicesRefConfig.REMEMBER_ME_SERVICES.loginSuccess(any(), any(), any())
        } returns Unit

        mockMvc.get("/")

        verify(exactly = 1) { RememberMeServicesRefConfig.REMEMBER_ME_SERVICES.autoLogin(any(),any()) }
        mockMvc.post("/login") {
            with(csrf())
        }
        verify(exactly = 2) { RememberMeServicesRefConfig.REMEMBER_ME_SERVICES.loginFail(any(), any()) }
        mockMvc.post("/login") {
            loginRememberMeRequest()
        }
        verify(exactly = 1) { RememberMeServicesRefConfig.REMEMBER_ME_SERVICES.loginSuccess(any(), any(), any()) }
    }

    @Test
    fun `Remember Me when authentication success handler then uses`() {
        this.spring.register(RememberMeSuccessHandlerConfig::class.java).autowire()
        mockkObject(RememberMeSuccessHandlerConfig.SUCCESS_HANDLER)
        justRun {
            RememberMeSuccessHandlerConfig.SUCCESS_HANDLER.onAuthenticationSuccess(any(), any(), any())
        }
        val mvcResult = mockMvc.post("/login") {
            loginRememberMeRequest()
        }.andReturn()

        val rememberMeCookie = mvcResult.response.getCookie("remember-me")
                ?: fail { "Missing remember-me cookie in login response" }
        mockMvc.get("/abc") {
            cookie(rememberMeCookie)
        }

        verify(exactly = 1) { RememberMeSuccessHandlerConfig.SUCCESS_HANDLER.onAuthenticationSuccess(any(), any(), any()) }
    }

    @Test
    fun `Remember Me when key then remember me works only for matching routes`() {
        this.spring.register(WithoutKeyConfig::class.java, KeyConfig::class.java).autowire()
        val withoutKeyMvcResult = mockMvc.post("/without-key/login") {
            loginRememberMeRequest()
        }.andReturn()
        val withoutKeyRememberMeCookie = withoutKeyMvcResult.response.getCookie("remember-me")
                ?: fail { "Missing remember-me cookie in without key login response" }
        mockMvc.get("/abc") {
            cookie(withoutKeyRememberMeCookie)
        }.andExpect {
            status { isFound() }
            redirectedUrl("http://localhost/login")
        }
        val keyMvcResult = mockMvc.post("/login") {
            loginRememberMeRequest()
        }.andReturn()
        val keyRememberMeCookie = keyMvcResult.response.getCookie("remember-me")
                ?: fail { "Missing remember-me cookie in key login response" }
        mockMvc.get("/abc") {
            cookie(keyRememberMeCookie)
        }.andExpect {
            status { isNotFound() }
        }
    }

    @Test
    fun `Remember Me when token repository then uses`() {
        this.spring.register(RememberMeTokenRepositoryConfig::class.java).autowire()
        mockkObject(RememberMeTokenRepositoryConfig.TOKEN_REPOSITORY)
        every {
            RememberMeTokenRepositoryConfig.TOKEN_REPOSITORY.createNewToken(any())
        } returns Unit
        mockMvc.post("/login") {
            loginRememberMeRequest()
        }
        verify(exactly = 1) { RememberMeTokenRepositoryConfig.TOKEN_REPOSITORY.createNewToken(any()) }
    }

    @Test
    fun `Remember Me when token validity seconds then cookie max age`() {
        this.spring.register(RememberMeTokenValidityConfig::class.java).autowire()
        mockMvc.post("/login") {
            loginRememberMeRequest()
        }.andExpect {
            cookie {
                maxAge("remember-me", 42)
            }
        }
    }

    @Test
    fun `Remember Me when using defaults then cookie max age`() {
        this.spring.register(RememberMeConfig::class.java).autowire()
        mockMvc.post("/login") {
            loginRememberMeRequest()
        }.andExpect {
            cookie {
                maxAge("remember-me", AbstractRememberMeServices.TWO_WEEKS_S)
            }
        }
    }

    @Test
    fun `Remember Me when use secure cookie then cookie secure`() {
        this.spring.register(RememberMeUseSecureCookieConfig::class.java).autowire()
        mockMvc.post("/login") {
            loginRememberMeRequest()
        }.andExpect {
            cookie {
                secure("remember-me", true)
            }
        }
    }

    @Test
    fun `Remember Me when using defaults then cookie secure`() {
        this.spring.register(RememberMeConfig::class.java).autowire()
        mockMvc.post("/login") {
            loginRememberMeRequest()
            secure = true
        }.andExpect {
            cookie {
                secure("remember-me", true)
            }
        }
    }

    @Test
    fun `Remember Me when parameter then responds with remember me cookie`() {
        this.spring.register(RememberMeParameterConfig::class.java).autowire()
        mockMvc.post("/login") {
            loginRememberMeRequest("rememberMe")
        }.andExpect {
            cookie {
                exists("remember-me")
            }
        }
    }

    @Test
    fun `Remember Me when cookie name then responds with remember me cookie with such name`() {
        this.spring.register(RememberMeCookieNameConfig::class.java).autowire()
        mockMvc.post("/login") {
            loginRememberMeRequest()
        }.andExpect {
            cookie {
                exists("rememberMe")
            }
        }
    }

    @Test
    fun `Remember Me when global user details service then uses`() {
        this.spring.register(RememberMeDefaultUserDetailsServiceConfig::class.java).autowire()
        mockkObject(RememberMeDefaultUserDetailsServiceConfig.USER_DETAIL_SERVICE)
        val user = User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER"))
        every {
            RememberMeDefaultUserDetailsServiceConfig.USER_DETAIL_SERVICE.loadUserByUsername("user")
        } returns user

        mockMvc.post("/login") {
            loginRememberMeRequest()
        }

        verify(exactly = 1) { RememberMeDefaultUserDetailsServiceConfig.USER_DETAIL_SERVICE.loadUserByUsername("user") }
    }

    @Test
    fun `Remember Me when user details service then uses`() {
        this.spring.register(RememberMeUserDetailsServiceConfig::class.java).autowire()
        mockkObject(RememberMeUserDetailsServiceConfig.USER_DETAIL_SERVICE)
        val user = User("user", "password", AuthorityUtils.createAuthorityList("ROLE_USER"))
        every {
            RememberMeUserDetailsServiceConfig.USER_DETAIL_SERVICE.loadUserByUsername("user")
        } returns user
        mockMvc.post("/login") {
            loginRememberMeRequest()
        }
        verify(exactly = 1) { RememberMeUserDetailsServiceConfig.USER_DETAIL_SERVICE.loadUserByUsername("user") }
    }

    @Test
    fun `Remember Me when always remember then remembers without HTTP parameter`() {
        this.spring.register(RememberMeAlwaysRememberConfig::class.java).autowire()
        mockMvc.post("/login") {
            loginRememberMeRequest(rememberMeValue = null)
        }.andExpect {
            cookie {
                exists("remember-me")
            }
        }
    }

    private fun MockHttpServletRequestDsl.loginRememberMeRequest(
        rememberMeParameter: String = "remember-me",
        rememberMeValue: Boolean? = true
    ) {
        with(csrf())
        param("username", "user")
        param("password", "password")
        rememberMeValue?.also {
            param(rememberMeParameter, rememberMeValue.toString())
        }
    }

    abstract class DefaultUserConfig : WebSecurityConfigurerAdapter() {
        @Autowired
        open fun configureGlobal(auth: AuthenticationManagerBuilder) {
            auth.inMemoryAuthentication()
                    .withUser(PasswordEncodedUser.user())
        }
    }

    @EnableWebSecurity
    open class RememberMeConfig : DefaultUserConfig() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, hasRole("USER"))
                }
                formLogin {}
                rememberMe {}
            }
        }
    }

    @EnableWebSecurity
    open class RememberMeDomainConfig : DefaultUserConfig() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, hasRole("USER"))
                }
                formLogin {}
                rememberMe {
                    rememberMeCookieDomain = "spring.io"
                }
            }
        }
    }

    @EnableWebSecurity
    open class RememberMeServicesRefConfig : DefaultUserConfig() {

        companion object {
            val REMEMBER_ME_SERVICES: RememberMeServices = NullRememberMeServices()
        }

        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                rememberMe {
                    rememberMeServices = REMEMBER_ME_SERVICES
                }
            }
        }
    }

    @EnableWebSecurity
    open class RememberMeSuccessHandlerConfig : DefaultUserConfig() {

        companion object {
            val SUCCESS_HANDLER: AuthenticationSuccessHandler = AuthenticationSuccessHandler { _ , _, _ -> }
        }

        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                rememberMe {
                    authenticationSuccessHandler = SUCCESS_HANDLER
                }
            }
        }
    }

    @EnableWebSecurity
    @Order(0)
    open class WithoutKeyConfig : DefaultUserConfig() {
        override fun configure(http: HttpSecurity) {
            http {
                securityMatcher(AntPathRequestMatcher("/without-key/**"))
                formLogin {
                    loginProcessingUrl = "/without-key/login"
                }
                rememberMe {}
            }
        }
    }

    @EnableWebSecurity
    open class KeyConfig : DefaultUserConfig() {
        override fun configure(http: HttpSecurity) {
            http {
                authorizeRequests {
                    authorize(anyRequest, authenticated)
                }
                formLogin {}
                rememberMe {
                    key = "RememberMeKey"
                }
            }
        }
    }

    @EnableWebSecurity
    open class RememberMeTokenRepositoryConfig : DefaultUserConfig() {

        companion object {
            val TOKEN_REPOSITORY: PersistentTokenRepository = mockk()
        }

        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                rememberMe {
                    tokenRepository = TOKEN_REPOSITORY
                }
            }
        }
    }

    @EnableWebSecurity
    open class RememberMeTokenValidityConfig : DefaultUserConfig() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                rememberMe {
                    tokenValiditySeconds = 42
                }
            }
        }
    }

    @EnableWebSecurity
    open class RememberMeUseSecureCookieConfig : DefaultUserConfig() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                rememberMe {
                    useSecureCookie = true
                }
            }
        }
    }

    @EnableWebSecurity
    open class RememberMeParameterConfig : DefaultUserConfig() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                rememberMe {
                    rememberMeParameter = "rememberMe"
                }
            }
        }
    }

    @EnableWebSecurity
    open class RememberMeCookieNameConfig : DefaultUserConfig() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                rememberMe {
                    rememberMeCookieName = "rememberMe"
                }
            }
        }
    }

    @EnableWebSecurity
    open class RememberMeDefaultUserDetailsServiceConfig : DefaultUserConfig() {

        companion object {
            val USER_DETAIL_SERVICE: UserDetailsService = UserDetailsService { _ ->
                User("username", "password", emptyList())
            }
            val PASSWORD_ENCODER: PasswordEncoder = BCryptPasswordEncoder()
        }

        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                rememberMe {}
            }
        }

        override fun configure(auth: AuthenticationManagerBuilder) {
            auth.userDetailsService(USER_DETAIL_SERVICE)
        }

        @Bean
        open fun delegatingPasswordEncoder(): PasswordEncoder = PASSWORD_ENCODER

    }

    @EnableWebSecurity
    open class RememberMeUserDetailsServiceConfig : DefaultUserConfig() {

        companion object {
            val USER_DETAIL_SERVICE: UserDetailsService = UserDetailsService { _ ->
                User("username", "password", emptyList())
            }
        }

        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                rememberMe {
                    userDetailsService = USER_DETAIL_SERVICE
                }
            }
        }
    }

    @EnableWebSecurity
    open class RememberMeAlwaysRememberConfig : DefaultUserConfig() {
        override fun configure(http: HttpSecurity) {
            http {
                formLogin {}
                rememberMe {
                    alwaysRemember = true
                }
            }
        }
    }

}
