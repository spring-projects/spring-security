package org.springframework.security.kt.docs.servlet.configuration.httpsecuritycustomizerbean

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.ThrowingCustomizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class HttpSecurityCustomizerBeanConfiguration {

    @Bean
    fun springSecurity(http: HttpSecurity): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize(anyRequest, authenticated)
            }
        }
        return http.build()
    }


    // tag::httpSecurityCustomizer[]
    @Bean
    fun httpSecurityCustomizer(): ThrowingCustomizer<HttpSecurity> {
        // @formatter:off
        return ThrowingCustomizer { http -> http
            .headers { headers -> headers
                .contentSecurityPolicy { csp -> csp
                    // <1>
                    .policyDirectives("object-src 'none'")
                }
            }
            // <2>
            .redirectToHttps(Customizer.withDefaults())
        }
        // @formatter:on
    }
    // end::httpSecurityCustomizer[]

}
