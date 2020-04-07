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

import org.springframework.security.web.PortMapper
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher
import org.springframework.web.server.ServerWebExchange

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] HTTPS redirection rules using idiomatic
 * Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 * @property portMapper the [PortMapper] that specifies a custom HTTPS port to redirect to.
 */
class ServerHttpsRedirectDsl {
    var portMapper: PortMapper? = null

    private var redirectMatchers: Array<out ServerWebExchangeMatcher>? = null
    private var redirectMatcherFunction: ((ServerWebExchange) -> Boolean)? = null

    /**
     * Configures when this filter should redirect to https.
     * If invoked multiple times, whether a matcher or a function is provided, only the
     * last redirect rule will apply and all previous rules will be overridden.
     *
     * @param redirectMatchers the list of conditions that, when any are met, the
     * filter should redirect to https.
     */
    fun httpsRedirectWhen(vararg redirectMatchers: ServerWebExchangeMatcher) {
        this.redirectMatcherFunction = null
        this.redirectMatchers = redirectMatchers
    }

    /**
     * Configures when this filter should redirect to https.
     * If invoked multiple times, whether a matcher or a function is provided, only the
     * last redirect rule will apply and all previous rules will be overridden.
     *
     * @param redirectMatcherFunction the condition in which the filter should redirect to
     * https.
     */
    fun httpsRedirectWhen(redirectMatcherFunction: (ServerWebExchange) -> Boolean) {
        this.redirectMatchers = null
        this.redirectMatcherFunction = redirectMatcherFunction
    }

    internal fun get(): (ServerHttpSecurity.HttpsRedirectSpec) -> Unit {
        return { httpsRedirect ->
            portMapper?.also { httpsRedirect.portMapper(portMapper) }
            redirectMatchers?.also { httpsRedirect.httpsRedirectWhen(*redirectMatchers!!) }
            redirectMatcherFunction?.also { httpsRedirect.httpsRedirectWhen(redirectMatcherFunction) }
        }
    }
}
