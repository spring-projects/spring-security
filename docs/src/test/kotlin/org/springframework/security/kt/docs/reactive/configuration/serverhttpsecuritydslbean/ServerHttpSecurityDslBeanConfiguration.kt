package org.springframework.security.kt.docs.reactive.configuration.serverhttpsecuritydslbean

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.ServerHttpSecurityDsl
import org.springframework.security.config.web.server.invoke
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.web.servlet.config.annotation.EnableWebMvc

@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
class ServerHttpSecurityDslBeanConfiguration {

    @Bean
    fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        return http {
            authorizeExchange {
                authorize(anyExchange, authenticated)
            }
        }
    }

    // tag::httpSecurityDslBean[]
    @Bean
    fun httpSecurityDslBean(): ServerHttpSecurityDsl.() -> Unit {
        return {
            headers {
                contentSecurityPolicy {
                    // <1>
                    policyDirectives = "object-src 'none'"
                }
            }
            // <2>
            redirectToHttps { }
        }
    }
    // end::httpSecurityDslBean[]

}
