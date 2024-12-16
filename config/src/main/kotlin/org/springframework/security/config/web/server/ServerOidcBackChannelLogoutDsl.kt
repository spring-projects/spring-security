/*
 * Copyright 2002-2023 the original author or authors.
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

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] OIDC 1.0 Back-Channel Logout support using idiomatic Kotlin code.
 *
 * @author Josh Cummings
 * @since 6.2
 */
@ServerSecurityMarker
class ServerOidcBackChannelLogoutDsl {
    private var _logoutUri: String? = null
    private var _logoutHandler: ServerLogoutHandler? = null

    var logoutHandler: ServerLogoutHandler?
        get() = _logoutHandler
        set(value) {
            _logoutHandler = value
            _logoutUri = null
        }
    var logoutUri: String?
        get() = _logoutUri
        set(value) {
            _logoutUri = value
            _logoutHandler = null
        }

    internal fun get(): (ServerHttpSecurity.OidcLogoutSpec.BackChannelLogoutConfigurer) -> Unit {
        return { backChannel ->
            logoutHandler?.also { backChannel.logoutHandler(logoutHandler) }
            logoutUri?.also { backChannel.logoutUri(logoutUri) }
        }
    }
}
