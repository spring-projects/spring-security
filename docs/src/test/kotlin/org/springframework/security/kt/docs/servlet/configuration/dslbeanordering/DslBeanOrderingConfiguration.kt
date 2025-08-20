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
package org.springframework.security.kt.docs.servlet.configuration.dslbeanordering

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.core.Ordered
import org.springframework.core.annotation.Order
import org.springframework.security.config.Customizer
import org.springframework.security.config.ThrowingCustomizer
import org.springframework.security.config.annotation.web.HeadersDsl
import org.springframework.security.config.annotation.web.HttpSecurityDsl
import org.springframework.security.config.annotation.web.HttpsRedirectDsl
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer
import org.springframework.security.config.annotation.web.configurers.HttpsRedirectConfigurer
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.servlet.config.annotation.EnableWebMvc

/**
 *
 */
@EnableWebMvc
@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
internal class DslBeanOrderingConfiguration {
    // tag::sample[]
    // All of the Java Modular Configuration is applied first <1>

    @Bean // <5>
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

    @Bean
    @Order(Ordered.LOWEST_PRECEDENCE)  // <3>
    fun userAuthorization(): HttpSecurityDsl.() -> Unit {
        // @formatter:off
        return {
            authorizeHttpRequests {
                authorize("/users/**", hasRole("USER"))
            }
        }
        // @formatter:on
    }

    @Bean
    @Order(Ordered.HIGHEST_PRECEDENCE) // <2>
    fun adminAuthorization(): HttpSecurityDsl.() -> Unit {
        // @formatter:off
        return {
            authorizeHttpRequests {
                authorize("/admins/**", hasRole("ADMIN"))
            }
        }
        // @formatter:on
    }

    // <4>

    @Bean
    fun contentSecurityPolicy(): HeadersDsl.() -> Unit {
        // @formatter:off
        return {
            contentSecurityPolicy {
                policyDirectives = "object-src 'none'"
            }
        }
        // @formatter:on
    }

    @Bean
    fun contentTypeOptions(): HeadersDsl.() -> Unit {
        // @formatter:off
        return {
            contentTypeOptions { }
        }
        // @formatter:on
    }

    @Bean
    fun httpsRedirect(): HttpsRedirectDsl.() -> Unit {
        // @formatter:off
        return { }
        // @formatter:on
    }
    // end::sample[]
}
