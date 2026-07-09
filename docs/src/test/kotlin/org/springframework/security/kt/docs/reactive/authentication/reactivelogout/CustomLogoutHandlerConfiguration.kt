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

package org.springframework.security.kt.docs.reactive.authentication.reactivelogout

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity
import org.springframework.security.config.web.server.ServerHttpSecurity
import org.springframework.security.config.web.server.invoke
import org.springframework.security.web.server.SecurityWebFilterChain
import org.springframework.security.web.server.authentication.logout.DelegatingServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.SecurityContextServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.WebSessionServerLogoutHandler
import org.springframework.web.reactive.config.EnableWebFlux

/**
 * Demonstrates a reactive logout configuration that invalidates the `WebSession`
 * on logout in addition to clearing the security context.
 *
 * @author lu1tr0n
 */
@EnableWebFlux
@EnableWebFluxSecurity
@Configuration(proxyBeanMethods = false)
class CustomLogoutHandlerConfiguration {

    // tag::customLogoutHandler[]
    @Bean
    fun http(http: ServerHttpSecurity): SecurityWebFilterChain {
        val customLogoutHandler = DelegatingServerLogoutHandler(
            SecurityContextServerLogoutHandler(), WebSessionServerLogoutHandler()
        )

        return http {
            authorizeExchange {
                authorize(anyExchange, authenticated)
            }
            logout {
                logoutHandler = customLogoutHandler
            }
        }
    }
    // end::customLogoutHandler[]

}
