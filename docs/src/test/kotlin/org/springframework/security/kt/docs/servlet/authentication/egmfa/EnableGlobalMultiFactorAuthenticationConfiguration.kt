package org.springframework.security.kt.docs.servlet.authentication.egmfa

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.authorization.EnableGlobalMultiFactorAuthentication
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

// tag::enable-global-mfa[]
@EnableGlobalMultiFactorAuthentication( authorities = [
    GrantedAuthorities.FACTOR_PASSWORD_AUTHORITY,
    GrantedAuthorities.FACTOR_OTT_AUTHORITY])
// end::enable-global-mfa[]
internal class EnableGlobalMultiFactorAuthenticationConfiguration {

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
