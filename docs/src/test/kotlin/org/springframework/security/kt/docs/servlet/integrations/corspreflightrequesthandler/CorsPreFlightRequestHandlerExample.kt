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

package org.springframework.security.kt.docs.servlet.integrations.corspreflightrequesthandler

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.web.SecurityFilterChain
import org.springframework.web.cors.PreFlightRequestHandler

@Configuration
@EnableWebSecurity
class CorsPreFlightRequestHandlerExample {

    @Bean
    fun preFlightRequestHandler(): PreFlightRequestHandler {
        return PreFlightRequestHandler { _, _ ->
            // custom preflight handling (for example, write CORS headers or complete the response)
        }
    }

    // tag::preflightRequestHandler[]
    @Bean
    fun springSecurity(http: HttpSecurity, preFlightRequestHandler: PreFlightRequestHandler): SecurityFilterChain {
        http {
            authorizeHttpRequests {
                authorize(anyRequest, authenticated)
            }
            cors {
                this.preFlightRequestHandler = preFlightRequestHandler
            }
        }
        return http.build()
    }
    // end::preflightRequestHandler[]

}
