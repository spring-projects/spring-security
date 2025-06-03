/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.config.annotation.web.oauth2.resourceserver

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.DPoPAuthenticationConfigurer
import org.springframework.security.web.authentication.AuthenticationConverter
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * A Kotlin DSL to configure DPoP support using idiomatic Kotlin code.
 *
 * @author Max Batischev
 * @property requestMatcher the [RequestMatcher] to use.
 * @property authenticationConverter the [AuthenticationConverter] to use.
 * @property successHandler the [AuthenticationSuccessHandler] to use.
 * @property failureHandler the [AuthenticationFailureHandler] to use.
 * @since 7.0
 */
class DPoPDsl {
    var requestMatcher: RequestMatcher? = null
    var authenticationConverter: AuthenticationConverter? = null
    var successHandler: AuthenticationSuccessHandler? = null
    var failureHandler: AuthenticationFailureHandler? = null

    internal fun get(): (DPoPAuthenticationConfigurer<HttpSecurity>) -> Unit {
        return { dpop ->
            requestMatcher?.also { dpop.requestMatcher(requestMatcher) }
            authenticationConverter?.also { dpop.authenticationConverter(authenticationConverter) }
            successHandler?.also { dpop.successHandler(successHandler) }
            failureHandler?.also { dpop.failureHandler(failureHandler) }
        }
    }
}
