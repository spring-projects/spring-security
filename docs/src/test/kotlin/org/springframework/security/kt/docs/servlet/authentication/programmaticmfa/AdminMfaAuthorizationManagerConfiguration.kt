package org.springframework.security.kt.docs.servlet.authentication.programmaticmfa

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authorization.*
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.Authentication
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.core.userdetails.PasswordEncodedUser
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler
import org.springframework.stereotype.Component
import java.util.function.Supplier

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
internal class AdminMfaAuthorizationManagerConfiguration {

    // tag::httpSecurity[]
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        // @formatter:off
        http {
            authorizeHttpRequests {
                // <1>
                authorize("/admin/**", hasRole("ADMIN"))
                // <2>
                authorize(anyRequest, authenticated)
            }
            formLogin { }
            oneTimeTokenLogin { }
        }
        // @formatter:on
        return http.build()
    }
    // end::httpSecurity[]

    // tag::authorizationManager[]
    @Component
    internal open class AdminMfaAuthorizationManager : AuthorizationManager<Object> {
        override fun authorize(
            authentication: Supplier<out Authentication?>, context: Object): AuthorizationResult {
            return if ("admin" == authentication.get().name) {
                var admins =
                    AllAuthoritiesAuthorizationManager.hasAllAuthorities<Any>(
                        FactorGrantedAuthority.OTT_AUTHORITY,
                        FactorGrantedAuthority.PASSWORD_AUTHORITY)
                // <1>
                admins.authorize(authentication, context)
            } else {
                // <2>
                AuthorizationDecision(true)
            }
        }
    }
    // end::authorizationManager[]

    // tag::authorizationManagerFactory[]
    @Bean
    fun authorizationManagerFactory(admins: AdminMfaAuthorizationManager): AuthorizationManagerFactory<Object> {
        val defaults = DefaultAuthorizationManagerFactory<Object>()
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
