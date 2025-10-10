package org.springframework.security.kt.docs.servlet.authentication.validduration

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
import java.time.Duration

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
internal class ValidDurationConfiguration {
    // tag::httpSecurity[]
    @Bean
    @Throws(Exception::class)
    fun securityFilterChain(http: HttpSecurity): SecurityFilterChain? {
        // @formatter:off
        // <1>
        val passwordIn30m = AuthorizationManagerFactories.multiFactor<Any>()
            .requireFactor( { factor -> factor
                .passwordAuthority()
                .validDuration(Duration.ofMinutes(30))
            })
            .build()
        // <2>
        val passwordInHour = AuthorizationManagerFactories.multiFactor<Any>()
            .requireFactor( { factor -> factor
                .passwordAuthority()
                .validDuration(Duration.ofHours(1))
            })
            .build()
        http {
            authorizeHttpRequests {
                // <3>
                authorize("/admin/**", passwordIn30m.hasRole("ADMIN"))
                // <4>
                authorize("/user/settings/**", passwordInHour.authenticated())
                // <5>
                authorize(anyRequest, authenticated)
            }
            // <6>
            formLogin { }
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
