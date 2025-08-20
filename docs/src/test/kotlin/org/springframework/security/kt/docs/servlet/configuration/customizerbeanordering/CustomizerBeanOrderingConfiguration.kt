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
package org.springframework.security.kt.docs.servlet.configuration.customizerbeanordering

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.ThrowingCustomizer
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.AuthorizeHttpRequestsConfigurer.AuthorizationManagerRequestMatcherRegistry
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer
import org.springframework.security.config.annotation.web.configurers.HttpsRedirectConfigurer
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.servlet.config.annotation.EnableWebMvc

/**
 *
 */
@EnableWebMvc
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
internal class CustomizerBeanOrderingConfiguration {
    // tag::sample[]
    @Bean // <4>
    fun springSecurity(http: HttpSecurity): SecurityFilterChain {
        // @formatter:off
        http
            .authorizeHttpRequests({ requests -> requests
                .anyRequest().authenticated()
            })
        return http.build()
        // @formatter:on
    }

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)  // <2>
    fun userAuthorization(): ThrowingCustomizer<HttpSecurity> {
        // @formatter:off
        return ThrowingCustomizer { http -> http
            .authorizeHttpRequests { requests -> requests
                .requestMatchers("/users/**").hasRole("USER")
            }
        }
        // @formatter:on
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // <1>
    fun adminAuthorization(): ThrowingCustomizer<HttpSecurity> {
        // @formatter:off
        return ThrowingCustomizer { http -> http
            .authorizeHttpRequests { requests -> requests
                .requestMatchers("/admins/**").hasRole("ADMIN")
            }
        }
        // @formatter:on
    }

    // <3>

    @Bean
    fun contentSecurityPolicy(): Customizer<HeadersConfigurer<HttpSecurity>> {
        // @formatter:off
        return Customizer { headers -> headers
            .contentSecurityPolicy { csp -> csp
                .policyDirectives("object-src 'none'")
            }
        }
        // @formatter:on
    }

    @Bean
    fun contentTypeOptions(): Customizer<HeadersConfigurer<HttpSecurity>> {
        // @formatter:off
        return Customizer { headers -> headers
            .contentTypeOptions(Customizer.withDefaults())
        }
        // @formatter:on
    }

    @Bean
    fun httpsRedirect(): Customizer<HttpsRedirectConfigurer<HttpSecurity>> {
        // @formatter:off
        return Customizer.withDefaults<HttpsRedirectConfigurer<HttpSecurity>>()
        // @formatter:on
    }
    // end::sample[]
}
