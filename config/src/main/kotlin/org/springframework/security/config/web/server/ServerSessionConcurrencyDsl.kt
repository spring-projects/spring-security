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

import org.springframework.security.core.session.ReactiveSessionRegistry
import org.springframework.security.web.server.authentication.ServerMaximumSessionsExceededHandler
import org.springframework.security.web.server.authentication.SessionLimit

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] Session Concurrency support using idiomatic Kotlin code.
 *
 * @author Marcus da Coregio
 * @since 6.3
 */
@ServerSecurityMarker
class ServerSessionConcurrencyDsl {
    var maximumSessions: SessionLimit? = null
    var maximumSessionsExceededHandler: ServerMaximumSessionsExceededHandler? = null
    var sessionRegistry: ReactiveSessionRegistry? = null

    internal fun get(): (ServerHttpSecurity.SessionManagementSpec.ConcurrentSessionsSpec) -> Unit {
        return { sessionConcurrency ->
            maximumSessions?.also {
                sessionConcurrency.maximumSessions(maximumSessions!!)
            }
            maximumSessionsExceededHandler?.also {
                sessionConcurrency.maximumSessionsExceededHandler(maximumSessionsExceededHandler!!)
            }
            sessionRegistry?.also {
                sessionConcurrency.sessionRegistry(sessionRegistry!!)
            }
        }
    }
}
