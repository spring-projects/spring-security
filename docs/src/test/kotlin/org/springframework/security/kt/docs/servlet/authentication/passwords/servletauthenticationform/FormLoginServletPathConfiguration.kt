package org.springframework.security.kt.docs.servlet.authentication.passwords.servletauthenticationform

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class FormLoginServletPathConfiguration {

    // tag::loginPage[]
    @Bean
    fun springSecurity(http: HttpSecurity): SecurityFilterChain {
        // @formatter:off
        http {
            authorizeHttpRequests {
                authorize(anyRequest, authenticated)
            }
            formLogin {
                loginPage = "/api/login"
                loginProcessingUrl = "/api/login"
            }
        }
        return http.build()
        // @formatter:on
    }
    // end::loginPage[]

}
