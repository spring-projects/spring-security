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

package org.springframework.security.config.web.server

import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler
import org.springframework.security.web.server.authentication.logout.ServerLogoutSuccessHandler
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] logout support using idiomatic Kotlin
 * code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property logoutHandler a [ServerLogoutHandler] that is invoked when logout occurs.
 * @property logoutUrl the URL that triggers logout to occur.
 * @property requiresLogout the [ServerWebExchangeMatcher] that triggers logout to occur.
 * @property logoutSuccessHandler the [ServerLogoutSuccessHandler] to use after logout has
 * occurred.
 */
@ServerSecurityMarker
class ServerLogoutDsl {
    var logoutHandler: ServerLogoutHandler? = null
    var logoutUrl: String? = null
    var requiresLogout: ServerWebExchangeMatcher? = null
    var logoutSuccessHandler: ServerLogoutSuccessHandler? = null

    private var disabled = false

    /**
     * Disables logout
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (ServerHttpSecurity.LogoutSpec) -> Unit {
        return { logout ->
            logoutHandler?.also { logout.logoutHandler(logoutHandler) }
            logoutUrl?.also { logout.logoutUrl(logoutUrl) }
            requiresLogout?.also { logout.requiresLogout(requiresLogout) }
            logoutSuccessHandler?.also { logout.logoutSuccessHandler(logoutSuccessHandler) }
            if (disabled) {
                logout.disable()
            }
        }
    }
}
