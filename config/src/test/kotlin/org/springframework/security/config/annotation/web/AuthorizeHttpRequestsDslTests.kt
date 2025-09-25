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

import io.mockk.every
import io.mockk.mockk
import io.mockk.verify
import jakarta.servlet.DispatcherType
import org.aopalliance.intercept.MethodInvocation
import org.assertj.core.api.Assertions.assertThatThrownBy
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.extension.ExtendWith
import org.springframework.beans.factory.UnsatisfiedDependencyException
import org.springframework.beans.factory.annotation.Autowired
import org.springframework.beans.factory.getBean
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.http.HttpMethod
import org.springframework.security.access.hierarchicalroles.RoleHierarchy
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl
import org.springframework.security.authentication.RememberMeAuthenticationToken
import org.springframework.security.authentication.TestAuthentication
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.authorization.AuthorizationManagerFactory
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.core.GrantedAuthorityDefaults
import org.springframework.security.config.test.SpringTestContext
import org.springframework.security.config.test.SpringTestContextExtension
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.AuthorityUtils
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.*
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import org.springframework.security.web.util.matcher.DispatcherTypeRequestMatcher
import org.springframework.security.web.util.matcher.RegexRequestMatcher
import org.springframework.test.web.servlet.MockMvc
import org.springframework.test.web.servlet.get
import org.springframework.test.web.servlet.post
import org.springframework.test.web.servlet.put
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders.put
import org.springframework.test.web.servlet.result.MockMvcResultMatchers.status
import org.springframework.web.bind.annotation.GetMapping
import org.springframework.web.bind.annotation.PathVariable
import org.springframework.web.bind.annotation.RequestMapping
import org.springframework.web.bind.annotation.RestController
import org.springframework.web.servlet.config.annotation.EnableWebMvc
import org.springframework.web.util.WebUtils
import java.util.function.Supplier

/**
 * Tests for [AuthorizeHttpRequestsDsl]
 *
 * @author Yuriy Savchenko
 */
@ExtendWith(SpringTestContextExtension::class)
class AuthorizeHttpRequestsDslTests {
    @JvmField
    val spring = SpringTestContext(this)

    @Autowired
    lateinit var mockMvc: MockMvc

    @Test
    fun `request when secured by regex matcher then responds with forbidden`() {
        this.spring.register(AuthorizeHttpRequestsByRegexConfig::class.java).autowire()

        this.mockMvc.get("/private")
            .andExpect {
                status { isForbidden() }
            }
    }

    @Test
    fun `request when allowed by regex matcher then responds with ok`() {
        this.spring.register(AuthorizeHttpRequestsByRegexConfig::class.java).autowire()

        this.mockMvc.get("/path")
            .andExpect {
                status { isOk() }
            }
    }

    @Test
    fun `request when allowed by regex matcher with http method then responds based on method`() {
        this.spring.register(AuthorizeHttpRequestsByRegexConfig::class.java).autowire()

        this.mockMvc.post("/onlyPostPermitted") { with(csrf()) }
            .andExpect {
                status { isOk() }
            }

        this.mockMvc.get("/onlyPostPermitted")
            .andExpect {
                status { isForbidden() }
            }
    }

    @Configuration
    @EnableWebSecurity
    open class AuthorizeHttpRequestsByRegexConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(RegexRequestMatcher("/path", null), permitAll)
                    authorize(RegexRequestMatcher("/onlyPostPermitted", "POST"), permitAll)
                    authorize(RegexRequestMatcher("/onlyPostPermitted", "GET"), denyAll)
                    authorize(RegexRequestMatcher(".*", null), authenticated)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path(): String {
                return "ok"
            }

            @RequestMapping("/onlyPostPermitted")
            fun onlyPostPermitted():String {
                return "ok"
            }
        }
    }

    @Test
    fun `request when secured by mvc then responds with forbidden`() {
        this.spring.register(AuthorizeHttpRequestsByMvcConfig::class.java).autowire()

        this.mockMvc.get("/private")
            .andExpect {
                status { isForbidden() }
            }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AuthorizeHttpRequestsByMvcConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/path", permitAll)
                    authorize("/**", authenticated)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }
    }

    @Test
    fun `request when secured by mvc path variables then responds based on path variable value`() {
        this.spring.register(MvcMatcherPathVariablesConfig::class.java).autowire()

        this.mockMvc.get("/user/user")
            .andExpect {
                status { isOk() }
            }

        this.mockMvc.get("/user/deny")
            .andExpect {
                status { isForbidden() }
            }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class MvcMatcherPathVariablesConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            val access = AuthorizationManager { _: Supplier<out Authentication>, context: RequestAuthorizationContext ->
                AuthorizationDecision(context.variables["userName"] == "user")
            }
            http {
                authorizeHttpRequests {
                    authorize("/user/{userName}", access)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/user/{user}")
            fun path(@PathVariable user: String) {
            }
        }
    }

    @Test
    fun `request when user has allowed role then responds with OK`() {
        this.spring.register(HasRoleConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("admin", "password"))
        }.andExpect {
            status { isOk() }
        }
    }

    @Test
    fun `request when user does not have allowed role then responds with forbidden`() {
        this.spring.register(HasRoleConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("user", "password"))
        }.andExpect {
            status { isForbidden() }
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class HasRoleConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/**", hasRole("ADMIN"))
                }
                httpBasic { }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index(): String {
                return "ok"
            }
        }

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build()
            val adminDetails = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build()
            return InMemoryUserDetailsManager(userDetails, adminDetails)
        }
    }

    @Test
    fun `request when user has some allowed roles then responds with OK`() {
        this.spring.register(HasAnyRoleConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("user", "password"))
        }.andExpect {
            status { isOk() }
        }

        this.mockMvc.get("/") {
            with(httpBasic("admin", "password"))
        }.andExpect {
            status { isOk() }
        }
    }

    @Test
    fun `request when user does not have any allowed roles then responds with forbidden`() {
        this.spring.register(HasAnyRoleConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("other", "password"))
        }.andExpect {
            status { isForbidden() }
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class HasAnyRoleConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/**", hasAnyRole("ADMIN", "USER"))
                }
                httpBasic { }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index(): String {
                return "ok"
            }
        }

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build()
            val admin1Details = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build()
            val admin2Details = User.withDefaultPasswordEncoder()
                .username("other")
                .password("password")
                .roles("OTHER")
                .build()
            return InMemoryUserDetailsManager(userDetails, admin1Details, admin2Details)
        }
    }

    @Test
    fun `request when user has allowed authority then responds with OK`() {
        this.spring.register(HasAuthorityConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("admin", "password"))
        }.andExpect {
            status { isOk() }
        }
    }

    @Test
    fun `request when user does not have allowed authority then responds with forbidden`() {
        this.spring.register(HasAuthorityConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("user", "password"))
        }.andExpect {
            status { isForbidden() }
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class HasAuthorityConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/**", hasAuthority("ROLE_ADMIN"))
                }
                httpBasic { }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index(): String {
                return "ok"
            }
        }

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build()
            val adminDetails = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build()
            return InMemoryUserDetailsManager(userDetails, adminDetails)
        }
    }

    @Test
    fun `request when user has some allowed authorities then responds with OK`() {
        this.spring.register(HasAnyAuthorityConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("user", "password"))
        }.andExpect {
            status { isOk() }
        }

        this.mockMvc.get("/") {
            with(httpBasic("admin", "password"))
        }.andExpect {
            status { isOk() }
        }
    }

    @Test
    fun `request when user does not have any allowed authorities then responds with forbidden`() {
        this.spring.register(HasAnyAuthorityConfig::class.java).autowire()

        this.mockMvc.get("/") {
            with(httpBasic("other", "password"))
        }.andExpect {
            status { isForbidden() }
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class HasAnyAuthorityConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/**", hasAnyAuthority("ROLE_ADMIN", "ROLE_USER"))
                }
                httpBasic { }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @GetMapping("/")
            fun index(): String {
                return  "ok"
            }
        }

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val userDetails = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .authorities("ROLE_USER")
                .build()
            val admin1Details = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .authorities("ROLE_ADMIN")
                .build()
            val admin2Details = User.withDefaultPasswordEncoder()
                .username("other")
                .password("password")
                .authorities("ROLE_OTHER")
                .build()
            return InMemoryUserDetailsManager(userDetails, admin1Details, admin2Details)
        }
    }

    @Test
    fun `request when secured by mvc with servlet path then responds based on servlet path`() {
        this.spring.register(MvcMatcherServletPathConfig::class.java).autowire()

        this.mockMvc.perform(get("/spring/path")
            .with { request ->
                request.servletPath = "/spring"
                request
            })
            .andExpect(status().isForbidden)

        this.mockMvc.perform(get("/other/path")
            .with { request ->
                request.servletPath = "/other"
                request
            })
            .andExpect(status().isForbidden)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class MvcMatcherServletPathConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/path", "/spring", denyAll)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }
    }

    @Test
    fun `request when secured by mvc with http method then responds based on http method`() {
        this.spring.register(AuthorizeRequestsByMvcConfigWithHttpMethod::class.java).autowire()

        this.mockMvc.get("/path")
            .andExpect {
                status { isOk() }
            }

        this.mockMvc.put("/path") { with(csrf()) }
            .andExpect {
                status { isForbidden() }
            }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AuthorizeRequestsByMvcConfigWithHttpMethod {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(HttpMethod.GET, "/path", permitAll)
                    authorize(HttpMethod.PUT, "/path", denyAll)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }
    }

    @Test
    fun `request when secured by mvc with servlet path and http method then responds based on path and method`() {
        this.spring.register(MvcMatcherServletPathHttpMethodConfig::class.java).autowire()

        this.mockMvc.perform(get("/spring/path")
            .with { request ->
                request.apply {
                    servletPath = "/spring"
                }
            })
            .andExpect(status().isForbidden)

        this.mockMvc.perform(put("/spring/path")
            .with { request ->
                request.apply {
                    servletPath = "/spring"
                    csrf()
                }
            })
            .andExpect(status().isForbidden)

        this.mockMvc.perform(get("/other/path")
            .with { request ->
                request.apply {
                    servletPath = "/other"
                }
            })
            .andExpect(status().isForbidden)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class MvcMatcherServletPathHttpMethodConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(HttpMethod.GET, "/path", "/spring", denyAll)
                    authorize(HttpMethod.PUT, "/path", "/spring", denyAll)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }
    }

    @Test
    fun `request when shouldFilterAllDispatcherTypes and denyAll and ERROR then responds with forbidden`() {
        this.spring.register(ShouldFilterAllDispatcherTypesTrueDenyAllConfig::class.java).autowire()

        this.mockMvc.perform(get("/path")
            .with { request ->
                request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error")
                request.apply {
                    dispatcherType = DispatcherType.ERROR
                }
            })
            .andExpect(status().isForbidden)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class ShouldFilterAllDispatcherTypesTrueDenyAllConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(anyRequest, denyAll)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }

    }

    @Test
    fun `request when shouldFilterAllDispatcherTypes and permitAll and ERROR then responds with ok`() {
        this.spring.register(ShouldFilterAllDispatcherTypesTruePermitAllConfig::class.java).autowire()

        this.mockMvc.perform(get("/path")
            .with { request ->
                request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error")
                request.apply {
                    dispatcherType = DispatcherType.ERROR
                }
            })
            .andExpect(status().isOk)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class ShouldFilterAllDispatcherTypesTruePermitAllConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(anyRequest, permitAll)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }

    }

    @Test
    fun `request when shouldFilterAllDispatcherTypes false and ERROR dispatcher then responds with ok`() {
        this.spring.register(ShouldFilterAllDispatcherTypesFalseAndDenyAllConfig::class.java).autowire()

        this.mockMvc.perform(get("/path")
            .with { request ->
                request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error")
                request.apply {
                    dispatcherType = DispatcherType.ERROR
                }
            })
            .andExpect(status().isOk)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class ShouldFilterAllDispatcherTypesFalseAndDenyAllConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(DispatcherTypeRequestMatcher(DispatcherType.ERROR), permitAll)
                    authorize(DispatcherTypeRequestMatcher(DispatcherType.ASYNC), permitAll)
                    authorize(anyRequest, denyAll)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }

    }

    @Test
    fun `request when shouldFilterAllDispatcherTypes omitted and ERROR dispatcher then responds with forbidden`() {
        this.spring.register(ShouldFilterAllDispatcherTypesOmittedAndDenyAllConfig::class.java).autowire()

        this.mockMvc.perform(get("/path")
            .with { request ->
                request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error")
                request.apply {
                    dispatcherType = DispatcherType.ERROR
                }
            })
            .andExpect(status().isForbidden)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class ShouldFilterAllDispatcherTypesOmittedAndDenyAllConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(anyRequest, denyAll)
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }

    }

    @Test
    fun `request when ip address does not match then responds with forbidden`() {
        this.spring.register(HasIpAddressConfig::class.java).autowire()

        this.mockMvc.perform(get("/path")
            .with { request ->
                request.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error")
                request.apply {
                    dispatcherType = DispatcherType.ERROR
                }
            })
            .andExpect(status().isForbidden)
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class HasIpAddressConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize(anyRequest, hasIpAddress("10.0.0.0/24"))
                }
            }
            return http.build()
        }

        @RestController
        internal class PathController {
            @RequestMapping("/path")
            fun path() {
            }
        }
    }

    @Test
    fun `hasRole when prefixed by configured role prefix should fail to configure`() {
        assertThatThrownBy { this.spring.register(RoleValidationConfig::class.java).autowire() }
            .isInstanceOf(UnsatisfiedDependencyException::class.java)
            .hasRootCauseInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining(
                "ROLE_JUNIPER should not start with ROLE_ since ROLE_ is automatically prepended when using hasAnyRole. Consider using hasAnyAuthority instead."
            )
        assertThatThrownBy { this.spring.register(RoleValidationConfig::class.java, GrantedAuthorityDefaultsConfig::class.java).autowire() }
            .isInstanceOf(UnsatisfiedDependencyException::class.java)
            .hasRootCauseInstanceOf(IllegalArgumentException::class.java)
            .hasMessageContaining(
                "CUSTOM_JUNIPER should not start with CUSTOM_ since CUSTOM_ is automatically prepended when using hasAnyRole. Consider using hasAnyAuthority instead."
            )
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class RoleValidationConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/role", hasAnyRole("ROLE_JUNIPER"))
                    authorize("/custom", hasRole("CUSTOM_JUNIPER"))
                }
            }
            return http.build()
        }
    }

    @Configuration
    open class GrantedAuthorityDefaultsConfig {
        @Bean
        open fun grantedAuthorityDefaults(): GrantedAuthorityDefaults {
            return GrantedAuthorityDefaults("CUSTOM_")
        }
    }

    @Test
    fun `hasRole when role hierarchy configured then honor hierarchy`() {
        this.spring.register(RoleHierarchyConfig::class.java).autowire()
        this.mockMvc.get("/protected") {
            with(httpBasic("admin", "password"))
        }.andExpect {
            status {
                isOk()
            }
        }
        this.mockMvc.get("/protected") {
            with(httpBasic("user", "password"))
        }.andExpect {
            status {
                isOk()
            }
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class RoleHierarchyConfig {

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/protected", hasRole("USER"))
                }
                httpBasic { }
            }
            return http.build()
        }

        @Bean
        open fun roleHierarchy(): RoleHierarchy {
            return RoleHierarchyImpl.fromHierarchy("ROLE_ADMIN > ROLE_USER")
        }

        @Bean
        open fun userDetailsService(): UserDetailsService {
            val user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build()
            val admin = User.withDefaultPasswordEncoder()
                .username("admin")
                .password("password")
                .roles("ADMIN")
                .build()
            return InMemoryUserDetailsManager(user, admin)
        }

        @RestController
        internal class PathController {

            @RequestMapping("/protected")
            fun path() {
            }

        }

    }

    @Test
    fun `request when fully authenticated configured then responds ok`() {
        this.spring.register(FullyAuthenticatedConfig::class.java).autowire()

        this.mockMvc.get("/path") {
            with(user("user").roles("USER"))
        }.andExpect {
            status {
                isOk()
            }
        }
    }

    @Test
    fun `request when fully authenticated configured and remember-me token then responds unauthorized`() {
        this.spring.register(FullyAuthenticatedConfig::class.java).autowire()
        val rememberMe = RememberMeAuthenticationToken("key", "user",
                AuthorityUtils.createAuthorityList("ROLE_USER"))

        this.mockMvc.get("/path") {
            with(user("user").roles("USER"))
            with(authentication(rememberMe))
        }.andExpect {
            status {
                isUnauthorized()
            }
        }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class FullyAuthenticatedConfig {
        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/path", fullyAuthenticated)
                }
                httpBasic {  }
                rememberMe {  }
            }
            return http.build()
        }

        @Bean
        open fun userDetailsService(): UserDetailsService = InMemoryUserDetailsManager(TestAuthentication.user())

        @RestController
        internal class PathController {
            @GetMapping("/path")
            fun path(): String {
                return "ok"
            }
        }
    }

    @Test
    fun `custom AuthorizationManagerFactory of RequestAuthorizationContext`() {
        this.spring.register(AuthorizationManagerFactoryRequestAuthorizationContextConfig::class.java).autowire()
        val authzManagerFactory =
            this.spring.context.getBean<AuthorizationManagerFactory<RequestAuthorizationContext>>()
        val authzManager = this.spring.context.getBean<AuthorizationManagerFactoryRequestAuthorizationContextConfig>().authorizationManager
        every { authzManager.authorize(any(), any()) } returns AuthorizationDecision(true)

        verify { authzManagerFactory.authenticated() }
        verify { authzManagerFactory.denyAll() }
        verify { authzManagerFactory.fullyAuthenticated() }
        verify { authzManagerFactory.hasAllAuthorities("USER", "ADMIN") }
        verify { authzManagerFactory.hasAllRoles("USER", "ADMIN") }
        verify { authzManagerFactory.hasAnyAuthority("USER", "ADMIN") }
        verify { authzManagerFactory.hasAnyRole("USER", "ADMIN") }
        verify { authzManagerFactory.hasAuthority("USER") }
        verify { authzManagerFactory.hasRole("USER") }
        verify { authzManagerFactory.permitAll() }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AuthorizationManagerFactoryRequestAuthorizationContextConfig {
        val authorizationManager: AuthorizationManager<RequestAuthorizationContext> = mockk()

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/authenticated", authenticated)
                    authorize("/denyAll", denyAll)
                    authorize("/fullyAuthenticated", fullyAuthenticated)
                    authorize("/hasAllAuthorities/user_admin", hasAllAuthorities("USER", "ADMIN"))
                    authorize("/hasAllRoles/user_admin", hasAllRoles("USER", "ADMIN"))
                    authorize("/hasAnyAuthority/user_admin", hasAnyAuthority("USER", "ADMIN"))
                    authorize("/hasAnyRole/user_admin", hasAnyRole("USER", "ADMIN"))
                    authorize("/hasAuthority/user", hasAuthority("USER"))
                    authorize("/hasRole/user", hasRole("USER"))
                    authorize("/permitAll", authenticated)
                }
                httpBasic { }
                rememberMe { }
            }
            return http.build()
        }

        @Bean
        open fun authorizationManagerFactory(): AuthorizationManagerFactory<RequestAuthorizationContext> {
            val factory: AuthorizationManagerFactory<RequestAuthorizationContext> = mockk()
            every { factory.authenticated() } returns this.authorizationManager
            every { factory.denyAll() } returns this.authorizationManager
            every { factory.fullyAuthenticated() } returns this.authorizationManager
            every { factory.hasAllAuthorities("USER", "ADMIN") } returns this.authorizationManager
            every { factory.hasAllRoles("USER", "ADMIN") } returns this.authorizationManager
            every { factory.hasAnyAuthority("USER", "ADMIN") } returns this.authorizationManager
            every { factory.hasAnyRole("USER", "ADMIN") } returns this.authorizationManager
            every { factory.hasAuthority(any()) } returns this.authorizationManager
            every { factory.hasRole(any()) } returns this.authorizationManager
            every { factory.permitAll() } returns this.authorizationManager

            return factory
        }

        @Bean
        open fun userDetailsService(): UserDetailsService = InMemoryUserDetailsManager(TestAuthentication.user())

        @RestController
        internal class OkController {
            @GetMapping("/**")
            fun ok(): String {
                return "ok"
            }
        }

    }

    @Test
    fun `custom AuthorizationManagerFactory of Object`() {
        this.spring.register(AuthorizationManagerFactoryObjectConfig::class.java).autowire()
        val authzManagerFactory =
            this.spring.context.getBean<AuthorizationManagerFactory<Object>>()
        val authzManager = this.spring.context.getBean<AuthorizationManagerFactoryObjectConfig>().authorizationManager
        every { authzManager.authorize(any(), any()) } returns AuthorizationDecision(true)

        verify { authzManagerFactory.authenticated() }
        verify { authzManagerFactory.denyAll() }
        verify { authzManagerFactory.fullyAuthenticated() }
        verify { authzManagerFactory.hasAllAuthorities("USER", "ADMIN") }
        verify { authzManagerFactory.hasAllRoles("USER", "ADMIN") }
        verify { authzManagerFactory.hasAnyAuthority("USER", "ADMIN") }
        verify { authzManagerFactory.hasAnyRole("USER", "ADMIN") }
        verify { authzManagerFactory.hasAuthority("USER") }
        verify { authzManagerFactory.hasRole("USER") }
        verify { authzManagerFactory.permitAll() }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AuthorizationManagerFactoryObjectConfig {
        val authorizationManager: AuthorizationManager<Object> = mockk()

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/authenticated", authenticated)
                    authorize("/denyAll", denyAll)
                    authorize("/fullyAuthenticated", fullyAuthenticated)
                    authorize("/hasAllAuthorities/user_admin", hasAllAuthorities("USER", "ADMIN"))
                    authorize("/hasAllRoles/user_admin", hasAllRoles("USER", "ADMIN"))
                    authorize("/hasAnyAuthority/user_admin", hasAnyAuthority("USER", "ADMIN"))
                    authorize("/hasAnyRole/user_admin", hasAnyRole("USER", "ADMIN"))
                    authorize("/hasAuthority/user", hasAuthority("USER"))
                    authorize("/hasRole/user", hasRole("USER"))
                    authorize("/permitAll", authenticated)
                }
                httpBasic {  }
                rememberMe {  }
            }
            return http.build()
        }

        @Bean
        open fun authorizationManagerFactory(): AuthorizationManagerFactory<Object> {
            val factory: AuthorizationManagerFactory<Object> = mockk()
            every { factory.authenticated() } returns this.authorizationManager
            every { factory.denyAll() } returns this.authorizationManager
            every { factory.fullyAuthenticated() } returns this.authorizationManager
            every { factory.hasAllAuthorities("USER", "ADMIN") } returns this.authorizationManager
            every { factory.hasAllRoles("USER", "ADMIN") } returns this.authorizationManager
            every { factory.hasAnyAuthority("USER", "ADMIN") } returns this.authorizationManager
            every { factory.hasAnyRole("USER", "ADMIN") } returns this.authorizationManager
            every { factory.hasAuthority(any()) } returns this.authorizationManager
            every { factory.hasRole(any()) } returns this.authorizationManager
            every { factory.permitAll() } returns this.authorizationManager

            return factory
        }

        @Bean
        open fun userDetailsService(): UserDetailsService = InMemoryUserDetailsManager(TestAuthentication.user())

        @RestController
        internal class OkController {
            @GetMapping("/**")
            fun ok(): String {
                return "ok"
            }
        }
    }

    @Test
    fun `custom AuthorizationManagerFactory of MethodInvocation`() {
        this.spring.register(AuthorizationManagerFactoryMethodInvocationConfig::class.java).autowire()
        val authzManagerFactory =
            this.spring.context.getBean<AuthorizationManagerFactory<MethodInvocation>>()

        verify(exactly = 0) { authzManagerFactory.authenticated() }
    }

    @Configuration
    @EnableWebSecurity
    @EnableWebMvc
    open class AuthorizationManagerFactoryMethodInvocationConfig {
        val authorizationManager: AuthorizationManager<MethodInvocation> = mockk()

        @Bean
        open fun securityFilterChain(http: HttpSecurity): SecurityFilterChain {
            http {
                authorizeHttpRequests {
                    authorize("/authenticated", authenticated)
                }
                httpBasic {  }
                rememberMe {  }
            }
            return http.build()
        }

        @Bean
        open fun authorizationManagerFactory(): AuthorizationManagerFactory<MethodInvocation> {
            val factory: AuthorizationManagerFactory<MethodInvocation> = mockk()
            every { factory.authenticated() } returns this.authorizationManager

            return factory
        }

        @Bean
        open fun userDetailsService(): UserDetailsService = InMemoryUserDetailsManager(TestAuthentication.user())

        @RestController
        internal class OkController {
            @GetMapping("/**")
            fun ok(): String {
                return "ok"
            }
        }
    }
}
