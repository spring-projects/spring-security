/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.config.annotation.web

import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.AnonymousConfigurer
import org.springframework.security.core.Authentication
import org.springframework.security.core.GrantedAuthority
import org.springframework.security.web.authentication.AnonymousAuthenticationFilter

/**
 * A Kotlin DSL to configure [HttpSecurity] anonymous authentication using idiomatic
 * Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property key the key to identify tokens created for anonymous authentication
 * @property principal the principal for [Authentication] objects of anonymous users
 * @property authorities the [Authentication.getAuthorities] for anonymous users
 * @property authenticationProvider the [AuthenticationProvider] used to validate an
 * anonymous user
 * @property authenticationFilter the [AnonymousAuthenticationFilter] used to populate
 * an anonymous user.
 */
@SecurityMarker
class AnonymousDsl {
    var key: String? = null
    var principal: Any? = null
    var authorities: List<GrantedAuthority>? = null
    var authenticationProvider: AuthenticationProvider? = null
    var authenticationFilter: AnonymousAuthenticationFilter? = null

    private var disabled = false

    /**
     * Disable anonymous authentication
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (AnonymousConfigurer<HttpSecurity>) -> Unit {
        return { anonymous ->
            key?.also { anonymous.key(key) }
            principal?.also { anonymous.principal(principal) }
            authorities?.also { anonymous.authorities(authorities) }
            authenticationProvider?.also { anonymous.authenticationProvider(authenticationProvider) }
            authenticationFilter?.also { anonymous.authenticationFilter(authenticationFilter) }
            if (disabled) {
                anonymous.disable()
            }
        }
    }
}
