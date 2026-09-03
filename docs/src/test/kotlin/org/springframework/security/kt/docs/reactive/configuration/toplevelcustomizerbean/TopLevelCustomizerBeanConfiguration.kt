package org.springframework.security.kt.docs.reactive.configuration.toplevelcustomizerbean

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.SecurityFilterChain
import org.springframework.security.web.server.SecurityWebFilterChain

@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
class TopLevelCustomizerBeanConfiguration {

    @Bean
    fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        // @formatter:off
        http
            .authorizeExchange({ exchanges -> exchanges
                .anyExchange().authenticated()
            })
        return http.build()
        // @formatter:on
    }

    // tag::headersCustomizer[]
    @Bean
    fun headersSecurity(): Customizer<ServerHttpSecurity.HeaderSpec> {
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
