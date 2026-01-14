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

package org.springframework.security.config.annotation.web.headers

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer
import org.springframework.security.web.util.matcher.RequestMatcher

/**
 * A Kotlin DSL to configure the [HttpSecurity] Content-Security-Policy header using
 * idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @author Ziqin Wang
 * @since 5.3
 */
@HeadersSecurityMarker
class ContentSecurityPolicyDsl {
    /**
     * The security policy directive(s) to be used in the response header.
     * The [policyDirectives] may contain `{code}` as placeholders for a generated secure
     * random nonce, e.g., `script-src 'self' 'nonce-{nonce}'`.
     */
    var policyDirectives: String? = null

    /** Includes the `Content-Security-Policy-Report-Only` header in the response. */
    var reportOnly: Boolean? = null

    /**
     * The name of the servlet request attribute for the generated nonce. Views can read
     * this attribute to render the nonce in HTML.
     * @since 7.1
     */
    var nonceAttributeName: String? = null

    /**
     * The [RequestMatcher] to use for determining when CSP should be applied.
     * The default is to enable CSP in every response if
     * [org.springframework.security.config.annotation.web.HeadersDsl.contentSecurityPolicy]
     * is configured.
     * You can configure either this property or [requireCspMatchers], but not both.
     * @since 7.1
     * @see requireCspMatchers
     */
    var requireCspMatcher: RequestMatcher? = null

    private var requireCspPathPatterns: Array<out String>? = null

    /**
     * Specify the matching path patterns for determining when CSP should be applied.
     * The default is to write CSP header in every response if
     * [org.springframework.security.config.annotation.web.HeadersDsl.contentSecurityPolicy]
     * is configured.
     * You can configure either this method or [requireCspMatcher], but not both.
     * @param pathPatterns the path patterns to be matched with a
     * [org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher]
     * @since 7.1
     * @see requireCspMatcher
     */
    fun requireCspMatchers(vararg pathPatterns: String) {
        requireCspPathPatterns = pathPatterns
    }

    internal fun get(): (HeadersConfigurer<HttpSecurity>.ContentSecurityPolicyConfig) -> Unit {
        return { contentSecurityPolicy ->
            policyDirectives?.also {
                contentSecurityPolicy.policyDirectives(policyDirectives)
            }
            reportOnly?.also {
                if (reportOnly!!) {
                    contentSecurityPolicy.reportOnly()
                }
            }
            nonceAttributeName?.also(contentSecurityPolicy::nonceAttributeName)
            requireCspMatcher?.also(contentSecurityPolicy::requireCspMatcher)
            requireCspPathPatterns?.also(contentSecurityPolicy::requireCspMatchers)
        }
    }
}
