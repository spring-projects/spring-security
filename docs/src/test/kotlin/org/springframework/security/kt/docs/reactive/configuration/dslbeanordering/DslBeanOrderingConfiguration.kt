/*
 * Copyright 2004-present the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.kt.docs.reactive.configuration.dslbeanordering

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.*
import org.springframework.security.web.server.SecurityWebFilterChain

/**
 *
 */
@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
internal class DslBeanOrderingConfiguration {
    // tag::sample[]
    // All of the Java Modular Configuration is applied first <1>

    @Bean // <5>
    fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        // @formatter:off
        return http {
            authorizeExchange {
                authorize(anyExchange, authenticated)
            }
        }
        // @formatter:on
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)  // <3>
    fun userAuthorization(): ServerHttpSecurityDsl.() -> Unit {
        // @formatter:off
        return {
            authorizeExchange {
                authorize("/users/**", hasRole("USER"))
            }
        }
        // @formatter:on
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // <2>
    fun adminAuthorization(): ServerHttpSecurityDsl.() -> Unit {
        // @formatter:off
        return {
            authorizeExchange {
                authorize("/admins/**", hasRole("ADMIN"))
            }
        }
        // @formatter:on
    }

    // <4>

    @Bean
    fun contentSecurityPolicy(): ServerHeadersDsl.() -> Unit {
        // @formatter:off
        return {
            contentSecurityPolicy {
                policyDirectives = "object-src 'none'"
            }
        }
        // @formatter:on
    }

    @Bean
    fun contentTypeOptions(): ServerHeadersDsl.() -> Unit {
        // @formatter:off
        return {
            contentTypeOptions { }
        }
        // @formatter:on
    }

    @Bean
    fun httpsRedirect(): ServerHttpsRedirectDsl.() -> Unit {
        // @formatter:off
        return { }
        // @formatter:on
    }
    // end::sample[]
}
