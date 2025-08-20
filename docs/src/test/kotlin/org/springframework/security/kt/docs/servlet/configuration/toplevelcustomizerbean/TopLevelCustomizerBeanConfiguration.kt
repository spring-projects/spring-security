package org.springframework.security.kt.docs.servlet.configuration.toplevelcustomizerbean

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class TopLevelCustomizerBeanConfiguration {

    @Bean
    fun springSecurity(http: HttpSecurity): SecurityFilterChain {
        // @formatter:off
        http {
            authorizeHttpRequests {
                authorize(anyRequest, authenticated)
            }
        }
        return http.build()
        // @formatter:on
    }

    // tag::headersCustomizer[]
    @Bean
    fun headersSecurity(): Customizer<HeadersConfigurer<HttpSecurity>> {
        // @formatter:off
        return Customizer { headers -> headers
            .contentSecurityPolicy { csp -> csp
                // <1>
                .policyDirectives("object-src 'none'")
            }
        }
        // @formatter:on
    }
    // end::headersCustomizer[]

}
