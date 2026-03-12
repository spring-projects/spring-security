package org.springframework.security.kt.docs.servlet.authentication.raammfa

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authorization.AuthorizationManagerFactory
import org.springframework.security.authorization.DefaultAuthorizationManagerFactory
import org.springframework.security.authorization.MapRequiredAuthoritiesRepository
import org.springframework.security.authorization.RequiredAuthoritiesAuthorizationManager
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.core.userdetails.PasswordEncodedUser
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
internal class RequiredAuthoritiesAuthorizationManagerConfiguration {
    // tag::httpSecurity[]
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        // @formatter:off
        http {
            authorizeHttpRequests {
                authorize("/admin/**", hasRole("ADMIN")) // <1>
                authorize(anyRequest, authenticated) // <2>
            }
            formLogin { }
            oneTimeTokenLogin { }
        }
        // @formatter:on
        return http.build()
    }
    // end::httpSecurity[]

    // tag::authorizationManager[]
    @Bean
    fun adminAuthorization(): RequiredAuthoritiesAuthorizationManager<Any> {
        // <1>
        val authorities = MapRequiredAuthoritiesRepository()
        authorities.saveRequiredAuthorities("admin", listOf(
            FactorGrantedAuthority.PASSWORD_AUTHORITY,
            FactorGrantedAuthority.OTT_AUTHORITY)
        )
        // <2>
        return RequiredAuthoritiesAuthorizationManager(authorities)
    }
    // end::authorizationManager[]


    // tag::authorizationManagerFactory[]
    @Bean
    fun authorizationManagerFactory(admins: RequiredAuthoritiesAuthorizationManager<Any>): AuthorizationManagerFactory<Any> {
        val defaults = DefaultAuthorizationManagerFactory<Any>()
        // <1>
        defaults.setAdditionalAuthorization(admins)
        // <2>
        return defaults
    }
    // end::authorizationManagerFactory[]

    @Bean
    fun users(): UserDetailsService {
        return InMemoryUserDetailsManager(PasswordEncodedUser.user(), PasswordEncodedUser.admin())
    }

    @Bean
    fun tokenGenerationSuccessHandler(): OneTimeTokenGenerationSuccessHandler {
        return RedirectOneTimeTokenGenerationSuccessHandler("/ott/sent")
    }
}
