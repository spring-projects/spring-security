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

package org.springframework.security.kt.docs.servlet.authentication.validatingaccountstatus

import org.springframework.context.annotation.Bean
import org.springframework.context.annotation.Configuration
import org.springframework.security.authentication.AccountStatusUserDetailsChecker
import org.springframework.security.authentication.ott.OneTimeTokenAuthenticationProvider
import org.springframework.security.authentication.ott.OneTimeTokenService
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.invoke
import org.springframework.security.core.userdetails.UserDetailsService
import org.springframework.security.web.SecurityFilterChain

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
class OneTimeTokenAccountStatusExample {

    @Bean
    fun filterChain(
        http: HttpSecurity,
        oneTimeTokenAuthenticationProvider: OneTimeTokenAuthenticationProvider
    ): SecurityFilterChain {
        // @formatter:off
        http {
            // ...
            formLogin { }
            oneTimeTokenLogin {
                authenticationProvider = oneTimeTokenAuthenticationProvider
            }
        }
        // @formatter:on
        return http.build()
    }

    // tag::userDetailsChecker[]
    @Bean
    fun oneTimeTokenAuthenticationProvider(
        oneTimeTokenService: OneTimeTokenService,
        userDetailsService: UserDetailsService
    ): OneTimeTokenAuthenticationProvider {
        val provider = OneTimeTokenAuthenticationProvider(oneTimeTokenService, userDetailsService)
        provider.setUserDetailsChecker(AccountStatusUserDetailsChecker())
        return provider
    }
    // end::userDetailsChecker[]

}
