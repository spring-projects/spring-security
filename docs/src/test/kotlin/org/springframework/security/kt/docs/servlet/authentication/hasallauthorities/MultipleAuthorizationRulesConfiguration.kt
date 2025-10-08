package org.springframework.security.kt.docs.servlet.authentication.hasallauthorities

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.GrantedAuthorities
import org.springframework.security.core.userdetails.User
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.provisioning.InMemoryUserDetailsManager
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.authentication.ott.OneTimeTokenGenerationSuccessHandler
import org.springframework.security.web.authentication.ott.RedirectOneTimeTokenGenerationSuccessHandler

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
internal class MultipleAuthorizationRulesConfiguration {

    // tag::httpSecurity[]
    @Bean
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        // @formatter:off
        http {
            authorizeHttpRequests {
                // <1>
                authorize("/admin/**", hasAllAuthorities(
                    "ROLE_ADMIN",
                    GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY,
                    GrantedAuthorities.FACTOR_OTT_AUTHORITY
                ))
                // <2>
                authorize(anyRequest, hasAllAuthorities(
                    "ROLE_USER",
                    GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY,
                    GrantedAuthorities.FACTOR_OTT_AUTHORITY
                ))
            }
            // <3>
            formLogin { }
            oneTimeTokenLogin {  }
        }
        // @formatter:on
        return http.build()
    }
    // end::httpSecurity[]

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
