/*
 * Copyright 2026-present the original author or authors.
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

package org.springframework.security.kt.docs.servlet.integrations.websocketsockjscsrf

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain

// tag::snippet[]
@Configuration
@EnableWebSecurity
open class WebSecurityConfig {

    @Bean
    open fun filterChain(http: HttpSecurity): SecurityFilterChain {
        http {
            csrf {
                // ignore our stomp endpoints since they are protected using Stomp headers
                ignoringRequestMatchers("/chat/**")
            }
            headers {
                frameOptions {
                    // allow same origin to frame our site to support iframe SockJS
                    sameOrigin = true
                }
            }
            authorizeHttpRequests {
                // ...
            }
            // ...
        }
        return http.build()
    }

}
// end::snippet[]