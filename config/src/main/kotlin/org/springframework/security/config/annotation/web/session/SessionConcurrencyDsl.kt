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

package org.springframework.security.config.annotation.web.session

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.SessionManagementConfigurer
import org.springframework.security.core.session.SessionRegistry
import org.springframework.security.web.authentication.session.SessionLimit
import org.springframework.security.web.session.SessionInformationExpiredStrategy
import org.springframework.util.Assert

/**
 * A Kotlin DSL to configure the behaviour of multiple sessions using idiomatic
 * Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property maximumSessions controls the maximum number of sessions for a user.
 * @property expiredUrl the URL to redirect to if a user tries to access a resource and
 * their session has been expired due to too many sessions for the current user.
 * @property expiredSessionStrategy determines the behaviour when an expired session
 * is detected.
 * @property maxSessionsPreventsLogin if true, prevents a user from authenticating when the
 * [maximumSessions] has been reached. Otherwise (default), the user who authenticates
 * is allowed access and an existing user's session is expired.
 * @property sessionRegistry the [SessionRegistry] implementation used.
 */
@SessionSecurityMarker
class SessionConcurrencyDsl {
    var maximumSessions: Int? = null
    var expiredUrl: String? = null
    var expiredSessionStrategy: SessionInformationExpiredStrategy? = null
    var maxSessionsPreventsLogin: Boolean? = null
    var sessionRegistry: SessionRegistry? = null
    private var sessionLimit: SessionLimit? = null

    fun maximumSessions(max: SessionLimit) {
        this.sessionLimit = max
    }

    internal fun get(): (SessionManagementConfigurer<HttpSecurity>.ConcurrencyControlConfigurer) -> Unit {
        Assert.isTrue(maximumSessions == null || sessionLimit == null, "You cannot specify maximumSessions as both an Int and a SessionLimit. Please use only one.")
        return { sessionConcurrencyControl ->
            maximumSessions?.also {
                sessionConcurrencyControl.maximumSessions(maximumSessions!!)
            }
            sessionLimit?.also {
                sessionConcurrencyControl.maximumSessions(sessionLimit!!)
            }
            expiredUrl?.also {
                sessionConcurrencyControl.expiredUrl(expiredUrl)
            }
            expiredSessionStrategy?.also {
                sessionConcurrencyControl.expiredSessionStrategy(expiredSessionStrategy)
            }
            maxSessionsPreventsLogin?.also {
                sessionConcurrencyControl.maxSessionsPreventsLogin(maxSessionsPreventsLogin!!)
            }
            sessionRegistry?.also {
                sessionConcurrencyControl.sessionRegistry(sessionRegistry)
            }
        }
    }
}
