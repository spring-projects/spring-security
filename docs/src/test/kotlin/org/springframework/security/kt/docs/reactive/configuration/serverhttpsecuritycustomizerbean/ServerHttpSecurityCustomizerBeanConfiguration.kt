package org.springframework.security.kt.docs.reactive.configuration.serverhttpsecuritycustomizerbean

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.Customizer
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain

@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
class ServerHttpSecurityCustomizerBeanConfiguration {

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


    // tag::httpSecurityCustomizer[]
    @Bean
    fun httpSecurityCustomizer(): Customizer<ServerHttpSecurity> {
        // @formatter:off
        return Customizer { http -> http
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
