package org.springframework.security.kt.docs.reactive.configuration.topleveldslbean

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHeadersDsl
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.web.server.SecurityWebFilterChain


@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
class TopLevelDslBeanConfiguration {

    @Bean
    fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            authorizeExchange {
                authorize(anyExchange, authenticated)
            }
        }
    }

    // tag::headersSecurity[]
    @Bean
    fun headersSecurity(): ServerHeadersDsl.() -> Unit {
        return {
            contentSecurityPolicy {
                // <1>
                policyDirectives = "object-src 'none'"
            }
        }
    }
    // end::headersSecurity[]
}
