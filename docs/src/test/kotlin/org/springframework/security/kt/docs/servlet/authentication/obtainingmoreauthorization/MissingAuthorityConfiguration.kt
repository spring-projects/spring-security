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
import org.springframework.security.core.GrantedAuthorities
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
    fun authz(): AuthorizationManagerFactory<Object> {
        return DefaultAuthorizationManagerFactory.builder<Object>()
                .requireAdditionalAuthorities(GrantedAuthorities.FACTOR_X509_AUTHORITY, GrantedAuthorities.FACTOR_AUTHORIZATION_CODE_AUTHORITY)
                .build()
    }
    // end::authorizationManagerFactoryBean[]

    @Bean
    fun clients(): ClientRegistrationRepository {
        return InMemoryClientRegistrationRepository(TestClientRegistrations.clientRegistration().build())
    }
}
