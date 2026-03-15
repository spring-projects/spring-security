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

package org.springframework.security.config.web.server

import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher

/**
 * A Kotlin DSL to configure the [ServerHttpSecurity] Content-Security-Policy header using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @author Ziqin Wang
 * @since 5.4
 */
@ServerSecurityMarker
class ServerContentSecurityPolicyDsl {
    /**
     * The security policy directive(s) to be used in the response header.
     * The `policyDirectives` may contain `{nonce}` as placeholders for a generated
     * secure random nonce, e.g., `script-src 'self' 'nonce-{nonce}'`.
     */
    var policyDirectives: String? = null

    /** Includes the `Content-Security-Policy-Report-Only` header in the response. */
    var reportOnly: Boolean? = null

    /**
     * The name of the request attribute for the generated nonce. Views can read this
     * attribute to render the nonce in HTML.
     * @since 7.1
     */
    var nonceAttributeName: String? = null

    /**
     * The [ServerWebExchangeMatcher] to use for determining when CSP should be applied.
     * The default is to enable CSP in every response if [ServerHeadersDsl.contentSecurityPolicy]
     * is configured.
     * You can configure either this property or [requireCspMatchers], but not both.
     * @since 7.1
     * @see requireCspMatchers
     */
    var requireCspMatcher: ServerWebExchangeMatcher? = null

    private var requireCspPathPatterns: Array<out String>? = null

    /**
     * Specify the matching path patterns for determining when CSP should be applied.
     * The default is to enable CSP in every response if [ServerHeadersDsl.contentSecurityPolicy]
     * is configured.
     * You can configure either this method or [requireCspMatcher], but not both.
     * @param pathPatterns the path patterns to be matched with a
     * [org.springframework.security.web.server.util.matcher.PathPatternParserServerWebExchangeMatcher]
     * @since 7.1
     * @see requireCspMatcher
     */
    fun requireCspMatchers(vararg pathPatterns: String) {
        requireCspPathPatterns = pathPatterns
    }

    internal fun get(): (ServerHttpSecurity.HeaderSpec.ContentSecurityPolicySpec) -> Unit {
        return { contentSecurityPolicy ->
            policyDirectives?.also {
                contentSecurityPolicy.policyDirectives(policyDirectives)
            }
            reportOnly?.also {
                contentSecurityPolicy.reportOnly(reportOnly!!)
            }
            nonceAttributeName?.also(contentSecurityPolicy::nonceAttributeName)
            requireCspMatcher?.also(contentSecurityPolicy::requireCspMatcher)
            requireCspPathPatterns?.also(contentSecurityPolicy::requireCspMatchers)
        }
    }
}
