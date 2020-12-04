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

import org.springframework.security.web.server.header.*

/**
 * A Kotlin DSL to configure [ServerHttpSecurity] headers using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.4
 */
@ServerSecurityMarker
class ServerHeadersDsl {
    private var contentTypeOptions: ((ServerHttpSecurity.HeaderSpec.ContentTypeOptionsSpec) -> Unit)? = null
    private var xssProtection: ((ServerHttpSecurity.HeaderSpec.XssProtectionSpec) -> Unit)? = null
    private var cacheControl: ((ServerHttpSecurity.HeaderSpec.CacheSpec) -> Unit)? = null
    private var hsts: ((ServerHttpSecurity.HeaderSpec.HstsSpec) -> Unit)? = null
    private var frameOptions: ((ServerHttpSecurity.HeaderSpec.FrameOptionsSpec) -> Unit)? = null
    private var contentSecurityPolicy: ((ServerHttpSecurity.HeaderSpec.ContentSecurityPolicySpec) -> Unit)? = null
    private var referrerPolicy: ((ServerHttpSecurity.HeaderSpec.ReferrerPolicySpec) -> Unit)? = null
    private var featurePolicyDirectives: String? = null
    private var permissionsPolicy: ((ServerHttpSecurity.HeaderSpec.PermissionsPolicySpec) -> Unit)? = null

    private var disabled = false

    /**
     * Configures the [ContentTypeOptionsServerHttpHeadersWriter] which inserts the <a href=
     * "https://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx"
     * >X-Content-Type-Options header</a>
     *
     * @param contentTypeOptionsConfig the customization to apply to the header
     */
    fun contentTypeOptions(contentTypeOptionsConfig: ServerContentTypeOptionsDsl.() -> Unit) {
        this.contentTypeOptions = ServerContentTypeOptionsDsl().apply(contentTypeOptionsConfig).get()
    }

    /**
     * <strong>Note this is not comprehensive XSS protection!</strong>
     *
     * <p>
     * Allows customizing the [XXssProtectionServerHttpHeadersWriter] which adds the <a href=
     * "https://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx"
     * >X-XSS-Protection header</a>
     * </p>
     *
     * @param xssProtectionConfig the customization to apply to the header
     */
    fun xssProtection(xssProtectionConfig: ServerXssProtectionDsl.() -> Unit) {
        this.xssProtection = ServerXssProtectionDsl().apply(xssProtectionConfig).get()
    }

    /**
     * Allows customizing the [CacheControlServerHttpHeadersWriter]. Specifically it adds
     * the following headers:
     * <ul>
     * <li>Cache-Control: no-cache, no-store, max-age=0, must-revalidate</li>
     * <li>Pragma: no-cache</li>
     * <li>Expires: 0</li>
     * </ul>
     *
     * @param cacheControlConfig the customization to apply to the headers
     */
    fun cache(cacheControlConfig: ServerCacheControlDsl.() -> Unit) {
        this.cacheControl = ServerCacheControlDsl().apply(cacheControlConfig).get()
    }

    /**
     * Allows customizing the [StrictTransportSecurityServerHttpHeadersWriter] which provides support
     * for <a href="https://tools.ietf.org/html/rfc6797">HTTP Strict Transport Security
     * (HSTS)</a>.
     *
     * @param hstsConfig the customization to apply to the header
     */
    fun hsts(hstsConfig: ServerHttpStrictTransportSecurityDsl.() -> Unit) {
        this.hsts = ServerHttpStrictTransportSecurityDsl().apply(hstsConfig).get()
    }

    /**
     * Allows customizing the [XFrameOptionsServerHttpHeadersWriter] which add the X-Frame-Options
     * header.
     *
     * @param frameOptionsConfig the customization to apply to the header
     */
    fun frameOptions(frameOptionsConfig: ServerFrameOptionsDsl.() -> Unit) {
        this.frameOptions = ServerFrameOptionsDsl().apply(frameOptionsConfig).get()
    }

    /**
     * Allows configuration for <a href="https://www.w3.org/TR/CSP2/">Content Security Policy (CSP) Level 2</a>.
     *
     * @param contentSecurityPolicyConfig the customization to apply to the header
     */
    fun contentSecurityPolicy(contentSecurityPolicyConfig: ServerContentSecurityPolicyDsl.() -> Unit) {
        this.contentSecurityPolicy = ServerContentSecurityPolicyDsl().apply(contentSecurityPolicyConfig).get()
    }

    /**
     * Allows configuration for <a href="https://www.w3.org/TR/referrer-policy/">Referrer Policy</a>.
     *
     * <p>
     * Configuration is provided to the [ReferrerPolicyServerHttpHeadersWriter] which support the writing
     * of the header as detailed in the W3C Technical Report:
     * </p>
     * <ul>
     *  <li>Referrer-Policy</li>
     * </ul>
     *
     * @param referrerPolicyConfig the customization to apply to the header
     */
    fun referrerPolicy(referrerPolicyConfig: ServerReferrerPolicyDsl.() -> Unit) {
        this.referrerPolicy = ServerReferrerPolicyDsl().apply(referrerPolicyConfig).get()
    }

    /**
     * Allows configuration for <a href="https://wicg.github.io/feature-policy/">Feature
     * Policy</a>.
     *
     * <p>
     * Calling this method automatically enables (includes) the Feature-Policy
     * header in the response using the supplied policy directive(s).
     * <p>
     *
     * @param policyDirectives policyDirectives the security policy directive(s)
     */
    fun featurePolicy(policyDirectives: String) {
        this.featurePolicyDirectives = policyDirectives
    }

    /**
     * Allows configuration for <a href="https://w3c.github.io/webappsec-permissions-policy/">Permissions
     * Policy</a>.
     *
     * <p>
     * Calling this method automatically enables (includes) the Permissions-Policy
     * header in the response using the supplied policy directive(s).
     * <p>
     *
     * @param permissionsPolicyConfig the customization to apply to the header
     */
    fun permissionsPolicy(permissionsPolicyConfig: ServerPermissionsPolicyDsl.() -> Unit) {
        this.permissionsPolicy = ServerPermissionsPolicyDsl().apply(permissionsPolicyConfig).get()
    }

    /**
     * Disables HTTP response headers.
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (ServerHttpSecurity.HeaderSpec) -> Unit {
        return { headers ->
            contentTypeOptions?.also {
                headers.contentTypeOptions(contentTypeOptions)
            }
            xssProtection?.also {
                headers.xssProtection(xssProtection)
            }
            cacheControl?.also {
                headers.cache(cacheControl)
            }
            hsts?.also {
                headers.hsts(hsts)
            }
            frameOptions?.also {
                headers.frameOptions(frameOptions)
            }
            contentSecurityPolicy?.also {
                headers.contentSecurityPolicy(contentSecurityPolicy)
            }
            featurePolicyDirectives?.also {
                headers.featurePolicy(featurePolicyDirectives)
            }
            permissionsPolicy?.also {
                headers.permissionsPolicy(permissionsPolicy)
            }
            referrerPolicy?.also {
                headers.referrerPolicy(referrerPolicy)
            }
            if (disabled) {
                headers.disable()
            }
        }
    }
}
