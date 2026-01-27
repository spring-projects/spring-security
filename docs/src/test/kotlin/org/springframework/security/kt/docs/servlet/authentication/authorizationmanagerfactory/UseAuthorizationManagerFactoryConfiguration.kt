package org.springframework.security.kt.docs.servlet.authentication.authorizationmanagerfactory

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authorization.AuthorizationManagerFactories
import org.springframework.security.authorization.AuthorizationManagerFactory
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.authority.FactorGrantedAuthority
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
internal class UseAuthorizationManagerFactoryConfiguration {
    // tag::httpSecurity[]
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        // @formatter:off
        http {
            authorizeHttpRequests {
                authorize("/admin/**", hasRole("ADMIN"))
                authorize(anyRequest, authenticated)
            }
            formLogin { }
            oneTimeTokenLogin { }
        }
        // @formatter:on
        return http.build()
    }
    // end::httpSecurity[]

    // tag::authorizationManagerFactoryBean[]
    @Bean
    fun authz(): AuthorizationManagerFactory<Any> {
        return AuthorizationManagerFactories.multiFactor<Any>()
            .requireFactors(
                FactorGrantedAuthority.PASSWORD_AUTHORITY,
                FactorGrantedAuthority.OTT_AUTHORITY
            )
            .build()
    }
    // end::authorizationManagerFactoryBean[]

    @Suppress("DEPRECATION")
    @Bean
    fun userDetailsService(): UserDetailsService {
        return InMemoryUserDetailsManager(
            User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .authorities("app")
                .build()
        )
    }

    @Bean
    fun tokenGenerationSuccessHandler(): OneTimeTokenGenerationSuccessHandler {
        return RedirectOneTimeTokenGenerationSuccessHandler("/ott/sent")
    }
}
