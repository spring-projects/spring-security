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

package org.springframework.security.config.web.servlet

import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer
import org.springframework.security.config.web.servlet.headers.*
import org.springframework.security.web.header.HeaderWriter
import org.springframework.security.web.header.writers.*
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter

/**
 * A Kotlin DSL to configure [HttpSecurity] headers using idiomatic Kotlin code.
 *
 * @author Eleftheria Stein
 * @since 5.3
 * @property defaultsDisabled whether all of the default headers should be included in the response
 */
@SecurityMarker
class HeadersDsl {
    private var contentTypeOptions: ((HeadersConfigurer<HttpSecurity>.ContentTypeOptionsConfig) -> Unit)? = null
    private var xssProtection: ((HeadersConfigurer<HttpSecurity>.XXssConfig) -> Unit)? = null
    private var cacheControl: ((HeadersConfigurer<HttpSecurity>.CacheControlConfig) -> Unit)? = null
    private var hsts: ((HeadersConfigurer<HttpSecurity>.HstsConfig) -> Unit)? = null
    private var frameOptions: ((HeadersConfigurer<HttpSecurity>.FrameOptionsConfig) -> Unit)? = null
    private var hpkp: ((HeadersConfigurer<HttpSecurity>.HpkpConfig) -> Unit)? = null
    private var contentSecurityPolicy: ((HeadersConfigurer<HttpSecurity>.ContentSecurityPolicyConfig) -> Unit)? = null
    private var referrerPolicy: ((HeadersConfigurer<HttpSecurity>.ReferrerPolicyConfig) -> Unit)? = null
    private var featurePolicyDirectives: String? = null
    private var disabled = false
    private var headerWriters = mutableListOf<HeaderWriter>()

    var defaultsDisabled: Boolean? = null

    /**
     * Configures the [XContentTypeOptionsHeaderWriter] which inserts the <a href=
     * "https://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx"
     * >X-Content-Type-Options header</a>
     *
     * @param contentTypeOptionsConfig the customization to apply to the header
     */
    fun contentTypeOptions(contentTypeOptionsConfig: ContentTypeOptionsDsl.() -> Unit) {
        this.contentTypeOptions = ContentTypeOptionsDsl().apply(contentTypeOptionsConfig).get()
    }

    /**
     * <strong>Note this is not comprehensive XSS protection!</strong>
     *
     * <p>
     * Allows customizing the [XXssProtectionHeaderWriter] which adds the <a href=
     * "https://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx"
     * >X-XSS-Protection header</a>
     * </p>
     *
     * @param xssProtectionConfig the customization to apply to the header
     */
    fun xssProtection(xssProtectionConfig: XssProtectionConfigDsl.() -> Unit) {
        this.xssProtection = XssProtectionConfigDsl().apply(xssProtectionConfig).get()
    }

    /**
     * Allows customizing the [CacheControlHeadersWriter]. Specifically it adds the
     * following headers:
     * <ul>
     * <li>Cache-Control: no-cache, no-store, max-age=0, must-revalidate</li>
     * <li>Pragma: no-cache</li>
     * <li>Expires: 0</li>
     * </ul>
     *
     * @param cacheControlConfig the customization to apply to the header
     */
    fun cacheControl(cacheControlConfig: CacheControlDsl.() -> Unit) {
        this.cacheControl = CacheControlDsl().apply(cacheControlConfig).get()
    }

    /**
     * Allows customizing the [HstsHeaderWriter] which provides support for <a
     * href="https://tools.ietf.org/html/rfc6797">HTTP Strict Transport Security
     * (HSTS)</a>.
     *
     * @param hstsConfig the customization to apply to the header
     */
    fun httpStrictTransportSecurity(hstsConfig: HttpStrictTransportSecurityDsl.() -> Unit) {
        this.hsts = HttpStrictTransportSecurityDsl().apply(hstsConfig).get()
    }

    /**
     * Allows customizing the [XFrameOptionsHeaderWriter] which add the X-Frame-Options
     * header.
     *
     * @param frameOptionsConfig the customization to apply to the header
     */
    fun frameOptions(frameOptionsConfig: FrameOptionsDsl.() -> Unit) {
        this.frameOptions = FrameOptionsDsl().apply(frameOptionsConfig).get()
    }

    /**
     * Allows customizing the [HpkpHeaderWriter] which provides support for <a
     * href="https://tools.ietf.org/html/rfc7469">HTTP Public Key Pinning (HPKP)</a>.
     *
     * @param hpkpConfig the customization to apply to the header
     */
    fun httpPublicKeyPinning(hpkpConfig: HttpPublicKeyPinningDsl.() -> Unit) {
        this.hpkp = HttpPublicKeyPinningDsl().apply(hpkpConfig).get()
    }

    /**
     * Allows configuration for <a href="https://www.w3.org/TR/CSP2/">Content Security Policy (CSP) Level 2</a>.
     *
     * <p>
     * Calling this method automatically enables (includes) the Content-Security-Policy header in the response
     * using the supplied security policy directive(s).
     * </p>
     *
     * @param contentSecurityPolicyConfig the customization to apply to the header
     */
    fun contentSecurityPolicy(contentSecurityPolicyConfig: ContentSecurityPolicyDsl.() -> Unit) {
        this.contentSecurityPolicy = ContentSecurityPolicyDsl().apply(contentSecurityPolicyConfig).get()
    }

    /**
     * Allows configuration for <a href="https://www.w3.org/TR/referrer-policy/">Referrer Policy</a>.
     *
     * <p>
     * Configuration is provided to the [ReferrerPolicyHeaderWriter] which support the writing
     * of the header as detailed in the W3C Technical Report:
     * </p>
     * <ul>
     *  <li>Referrer-Policy</li>
     * </ul>
     *
     * @param referrerPolicyConfig the customization to apply to the header
     */
    fun referrerPolicy(referrerPolicyConfig: ReferrerPolicyDsl.() -> Unit) {
        this.referrerPolicy = ReferrerPolicyDsl().apply(referrerPolicyConfig).get()
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
     * Adds a [HeaderWriter] instance.
     *
     * @param headerWriter the [HeaderWriter] instance to add
     * @since 5.4
     */
    fun addHeaderWriter(headerWriter: HeaderWriter) {
        this.headerWriters.add(headerWriter)
    }

    /**
     * Disable all HTTP security headers.
     *
     * @since 5.4
     */
    fun disable() {
        disabled = true
    }

    internal fun get(): (HeadersConfigurer<HttpSecurity>) -> Unit {
        return { headers ->
            defaultsDisabled?.also {
                if (defaultsDisabled!!) {
                    headers.defaultsDisabled()
                }
            }
            contentTypeOptions?.also {
                headers.contentTypeOptions(contentTypeOptions)
            }
            xssProtection?.also {
                headers.xssProtection(xssProtection)
            }
            cacheControl?.also {
                headers.cacheControl(cacheControl)
            }
            hsts?.also {
                headers.httpStrictTransportSecurity(hsts)
            }
            frameOptions?.also {
                headers.frameOptions(frameOptions)
            }
            hpkp?.also {
                headers.httpPublicKeyPinning(hpkp)
            }
            contentSecurityPolicy?.also {
                headers.contentSecurityPolicy(contentSecurityPolicy)
            }
            referrerPolicy?.also {
                headers.referrerPolicy(referrerPolicy)
            }
            featurePolicyDirectives?.also {
                headers.featurePolicy(featurePolicyDirectives)
            }
            headerWriters.forEach { headerWriter ->
                headers.addHeaderWriter(headerWriter)
            }
            if (disabled) {
                headers.disable()
            }
        }
    }
}
