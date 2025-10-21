package org.springframework.security.kt.docs.servlet.authentication.selectivemfa

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
internal class SelectiveMfaConfiguration {
    // tag::httpSecurity[]
    @Bean
    @Throws(Exception::class)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        // @formatter:off
        // <1>
        val mfa = AuthorizationManagerFactories.multiFactor<Any>()
            .requireFactors(
                FactorGrantedAuthority.PASSWORD_AUTHORITY,
                FactorGrantedAuthority.OTT_AUTHORITY
            )
            .build()
        http {
            authorizeHttpRequests {
                // <2>
                authorize("/admin/**", mfa.hasRole("ADMIN"))
                // <3>
                authorize("/user/settings/**", mfa.authenticated())
                // <4>
                authorize(anyRequest, authenticated)
            }
            // <5>
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
