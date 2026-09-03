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

package org.springframework.security.kt.docs.reactive.configuration.customizerbeanordering

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.ThrowingCustomizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer
import org.springframework.security.config.annotation.web.configurers.HttpsRedirectConfigurer
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.anyExchange

/**
 *
 */
@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
internal class CustomizerBeanOrderingConfiguration {
    // tag::sample[]
    @Bean // <4>
    fun springSecurity(http: ServerHttpSecurity): SecurityWebFilterChain {
        // @formatter:off
        http
            .authorizeExchange({ exchanges -> exchanges
                .anyExchange().authenticated()
            })
        return http.build()
        // @formatter:on
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)  // <2>
    fun userAuthorization(): Customizer<ServerHttpSecurity> {
        // @formatter:off
        return Customizer { http -> http
            .authorizeExchange { exchanges -> exchanges
                .pathMatchers("/users/**").hasRole("USER")
            }
        }
        // @formatter:on
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // <1>
    fun adminAuthorization(): Customizer<ServerHttpSecurity> {
        // @formatter:off
        return ThrowingCustomizer { http -> http
            .authorizeExchange { exchanges -> exchanges
                .pathMatchers("/admins/**").hasRole("ADMIN")
            }
        }
        // @formatter:on
    }

    // <3>

    @Bean
    fun contentSecurityPolicy(): Customizer<ServerHttpSecurity.HeaderSpec> {
        // @formatter:off
        return Customizer { headers -> headers
            .contentSecurityPolicy { csp -> csp
                .policyDirectives("object-src 'none'")
            }
        }
        // @formatter:on
    }

    @Bean
    fun contentTypeOptions(): Customizer<ServerHttpSecurity.HeaderSpec> {
        // @formatter:off
        return Customizer { headers -> headers
            .contentTypeOptions(Customizer.withDefaults())
        }
        // @formatter:on
    }

    @Bean
    fun httpsRedirect(): Customizer<ServerHttpSecurity.HttpsRedirectSpec> {
        // @formatter:off
        return Customizer.withDefaults()
        // @formatter:on
    }
    // end::sample[]
}
