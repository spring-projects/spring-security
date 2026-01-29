package org.springframework.security.kt.docs.servlet.authentication.reauthentication

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
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
class RequireOttConfiguration {

    // tag::httpSecurity[]
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        // @formatter:off
        http {
            authorizeHttpRequests {
                authorize("/profile/**", hasAuthority(FactorGrantedAuthority.OTT_AUTHORITY)) // <1>
                authorize(anyRequest, authenticated)
            }
            formLogin { }
            oneTimeTokenLogin { }
        }
        // @formatter:on
        return http.build()
    }
    // end::httpSecurity[]

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
