package org.springframework.security.kt.docs.servlet.configuration.topleveldslbean

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.HeadersDsl
import org.springframework.security.config.annotation.web.HttpSecurityDsl
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.servlet.config.annotation.EnableWebMvc


@EnableWebMvc
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class TopLevelDslBeanConfiguration {

    @Bean
    fun springSecurity(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize(anyRequest, authenticated)
            }
        }
        return http.build()
    }

    // tag::headersSecurity[]
    @Bean
    fun headersSecurity(): HeadersDsl.() -> Unit {
        return {
            contentSecurityPolicy {
                // <1>
                policyDirectives = "object-src 'none'"
            }
        }
    }
    // end::headersSecurity[]
}
