package org.springframework.security.kt.docs.servlet.authentication.obtainingmoreauthorization

import jakarta.servlet.http.HttpServletRequest
import jakarta.servlet.http.HttpServletResponse
import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authorization.AllAuthoritiesAuthorizationManager.hasAllAuthorities
import org.springframework.security.authorization.AuthorizationDecision
import org.springframework.security.authorization.AuthorizationManager
import org.springframework.security.authorization.AuthorizationManagerFactory
import org.springframework.security.authorization.AuthorizationManagers.allOf
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.AuthenticationException
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository
import org.springframework.security.oauth2.client.registration.TestClientRegistrations
import org.springframework.security.web.AuthenticationEntryPoint
import org.springframework.security.web.DefaultSecurityFilterChain
import org.springframework.security.web.access.intercept.RequestAuthorizationContext
import org.springframework.stereotype.Component

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
internal class MissingAuthorityConfiguration {

    // tag::httpSecurity[]
    @Bean
    fun securityFilterChain(http: HttpSecurity, oauth2: ScopeRetrievingAuthenticationEntryPoint): DefaultSecurityFilterChain? {
        http {
            authorizeHttpRequests {
                authorize("/profile/**", hasAuthority("SCOPE_profile:read"))
                authorize(anyRequest, authenticated)
            }
            x509 { }
            oauth2Login { }
        }

        http.exceptionHandling { e: ExceptionHandlingConfigurer<HttpSecurity> -> e
            .defaultDeniedHandlerForMissingAuthority(oauth2, "SCOPE_profile:read")
        }
        return http.build()
    }
    // end::httpSecurity[]

    // tag::authenticationEntryPoint[]
    @Component
    internal class ScopeRetrievingAuthenticationEntryPoint : AuthenticationEntryPoint {
        override fun commence(request: HttpServletRequest, response: HttpServletResponse, authException: AuthenticationException) {
            response.sendRedirect("https://authz.example.org/authorize?scope=profile:read")
        }
    }
    // end::authenticationEntryPoint[]

    // tag::authorizationManagerFactoryBean[]
    @Bean
    fun authz(): AuthorizationManagerFactory<RequestAuthorizationContext> {
        return FactorAuthorizationManagerFactory(hasAllAuthorities("FACTOR_X509", "FACTOR_AUTHORIZATION_CODE"))
    }
    // end::authorizationManagerFactoryBean[]

    // tag::authorizationManagerFactory[]
    internal inner class FactorAuthorizationManagerFactory(private val hasAuthorities: AuthorizationManager<RequestAuthorizationContext>) :
        AuthorizationManagerFactory<RequestAuthorizationContext> {
        private val delegate = DefaultAuthorizationManagerFactory<RequestAuthorizationContext>()

        override fun permitAll(): AuthorizationManager<RequestAuthorizationContext> {
            return this.delegate.permitAll()
        }

        override fun denyAll(): AuthorizationManager<RequestAuthorizationContext> {
            return this.delegate.denyAll()
        }

        override fun hasRole(role: String): AuthorizationManager<RequestAuthorizationContext> {
            return hasAnyRole(role)
        }

        override fun hasAnyRole(vararg roles: String): AuthorizationManager<RequestAuthorizationContext> {
            return addFactors(this.delegate.hasAnyRole(*roles))
        }

        override fun hasAllRoles(vararg roles: String): AuthorizationManager<RequestAuthorizationContext> {
            return addFactors(this.delegate.hasAllRoles(*roles))
        }

        override fun hasAuthority(authority: String): AuthorizationManager<RequestAuthorizationContext> {
            return hasAnyAuthority(authority)
        }

        override fun hasAnyAuthority(vararg authorities: String): AuthorizationManager<RequestAuthorizationContext> {
            return addFactors(this.delegate.hasAnyAuthority(*authorities))
        }

        override fun hasAllAuthorities(vararg authorities: String): AuthorizationManager<RequestAuthorizationContext> {
            return addFactors(this.delegate.hasAllAuthorities(*authorities))
        }

        override fun authenticated(): AuthorizationManager<RequestAuthorizationContext> {
            return addFactors(this.delegate.authenticated())
        }

        override fun fullyAuthenticated(): AuthorizationManager<RequestAuthorizationContext> {
            return addFactors(this.delegate.fullyAuthenticated())
        }

        override fun rememberMe(): AuthorizationManager<RequestAuthorizationContext> {
            return addFactors(this.delegate.rememberMe())
        }

        override fun anonymous(): AuthorizationManager<RequestAuthorizationContext> {
            return this.delegate.anonymous()
        }

        private fun addFactors(delegate: AuthorizationManager<RequestAuthorizationContext>): AuthorizationManager<RequestAuthorizationContext> {
            return allOf(AuthorizationDecision(false), this.hasAuthorities, delegate)
        }
    }
    // end::authorizationManagerFactory[]

    // end::authenticationEntryPoint[]
    @Bean
    fun clients(): ClientRegistrationRepository {
        return InMemoryClientRegistrationRepository(TestClientRegistrations.clientRegistration().build())
    }
}
