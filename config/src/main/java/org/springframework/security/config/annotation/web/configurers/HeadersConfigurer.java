/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.header.HeaderWriter;
import org.springframework.security.web.header.HeaderWriterFilter;
import org.springframework.security.web.header.writers.CacheControlHeadersWriter;
import org.springframework.security.web.header.writers.ContentSecurityPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginEmbedderPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginOpenerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.CrossOriginResourcePolicyHeaderWriter;
import org.springframework.security.web.header.writers.FeaturePolicyHeaderWriter;
import org.springframework.security.web.header.writers.HpkpHeaderWriter;
import org.springframework.security.web.header.writers.HstsHeaderWriter;
import org.springframework.security.web.header.writers.PermissionsPolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter;
import org.springframework.security.web.header.writers.ReferrerPolicyHeaderWriter.ReferrerPolicy;
import org.springframework.security.web.header.writers.XContentTypeOptionsHeaderWriter;
import org.springframework.security.web.header.writers.XXssProtectionHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter.XFrameOptionsMode;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * <p>
 * Adds the Security HTTP headers to the response. Security HTTP headers is activated by
 * default when using {@link EnableWebSecurity}'s default constructor.
 * </p>
 *
 * <p>
 * The default headers include are:
 * </p>
 *
 * <pre>
 * Cache-Control: no-cache, no-store, max-age=0, must-revalidate
 * Pragma: no-cache
 * Expires: 0
 * X-Content-Type-Options: nosniff
 * Strict-Transport-Security: max-age=31536000 ; includeSubDomains
 * X-Frame-Options: DENY
 * X-XSS-Protection: 0
 * </pre>
 *
 * @author Rob Winch
 * @author Tim Ysewyn
 * @author Joe Grandja
 * @author Eddú Meléndez
 * @author Vedran Pavic
 * @author Ankur Pathak
 * @author Daniel Garnier-Moiroux
 * @since 3.2
 */
public class HeadersConfigurer<H extends HttpSecurityBuilder<H>>
		extends AbstractHttpConfigurer<HeadersConfigurer<H>, H> {

	private List<HeaderWriter> headerWriters = new ArrayList<>();

	private final ContentTypeOptionsConfig contentTypeOptions = new ContentTypeOptionsConfig();

	private final XXssConfig xssProtection = new XXssConfig();

	private final CacheControlConfig cacheControl = new CacheControlConfig();

	private final HstsConfig hsts = new HstsConfig();

	private final FrameOptionsConfig frameOptions = new FrameOptionsConfig();

	private final HpkpConfig hpkp = new HpkpConfig();

	private final ContentSecurityPolicyConfig contentSecurityPolicy = new ContentSecurityPolicyConfig();

	private final ReferrerPolicyConfig referrerPolicy = new ReferrerPolicyConfig();

	private final FeaturePolicyConfig featurePolicy = new FeaturePolicyConfig();

	private final PermissionsPolicyConfig permissionsPolicy = new PermissionsPolicyConfig();

	private final CrossOriginOpenerPolicyConfig crossOriginOpenerPolicy = new CrossOriginOpenerPolicyConfig();

	private final CrossOriginEmbedderPolicyConfig crossOriginEmbedderPolicy = new CrossOriginEmbedderPolicyConfig();

	private final CrossOriginResourcePolicyConfig crossOriginResourcePolicy = new CrossOriginResourcePolicyConfig();

	/**
	 * Creates a new instance
	 *
	 * @see HttpSecurity#headers()
	 */
	public HeadersConfigurer() {
	}

	/**
	 * Adds a {@link HeaderWriter} instance
	 * @param headerWriter the {@link HeaderWriter} instance to add
	 * @return the {@link HeadersConfigurer} for additional customizations
	 */
	public HeadersConfigurer<H> addHeaderWriter(HeaderWriter headerWriter) {
		Assert.notNull(headerWriter, "headerWriter cannot be null");
		this.headerWriters.add(headerWriter);
		return this;
	}

	/**
	 * Configures the {@link XContentTypeOptionsHeaderWriter} which inserts the
	 * <a href= "https://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx"
	 * >X-Content-Type-Options</a>:
	 *
	 * <pre>
	 * X-Content-Type-Options: nosniff
	 * </pre>
	 * @return the {@link ContentTypeOptionsConfig} for additional customizations
	 */
	public ContentTypeOptionsConfig contentTypeOptions() {
		return this.contentTypeOptions.enable();
	}

	/**
	 * Configures the {@link XContentTypeOptionsHeaderWriter} which inserts the
	 * <a href= "https://msdn.microsoft.com/en-us/library/ie/gg622941(v=vs.85).aspx"
	 * >X-Content-Type-Options</a>:
	 *
	 * <pre>
	 * X-Content-Type-Options: nosniff
	 * </pre>
	 * @param contentTypeOptionsCustomizer the {@link Customizer} to provide more options
	 * for the {@link ContentTypeOptionsConfig}
	 * @return the {@link HeadersConfigurer} for additional customizations
	 */
	public HeadersConfigurer<H> contentTypeOptions(Customizer<ContentTypeOptionsConfig> contentTypeOptionsCustomizer) {
		contentTypeOptionsCustomizer.customize(this.contentTypeOptions.enable());
		return HeadersConfigurer.this;
	}

	/**
	 * <strong>Note this is not comprehensive XSS protection!</strong>
	 *
	 * <p>
	 * Allows customizing the {@link XXssProtectionHeaderWriter} which adds the <a href=
	 * "https://web.archive.org/web/20160201174302/https://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx"
	 * >X-XSS-Protection header</a>
	 * </p>
	 * @return the {@link XXssConfig} for additional customizations
	 */
	public XXssConfig xssProtection() {
		return this.xssProtection.enable();
	}

	/**
	 * <strong>Note this is not comprehensive XSS protection!</strong>
	 *
	 * <p>
	 * Allows customizing the {@link XXssProtectionHeaderWriter} which adds the <a href=
	 * "https://web.archive.org/web/20160201174302/https://blogs.msdn.com/b/ieinternals/archive/2011/01/31/controlling-the-internet-explorer-xss-filter-with-the-x-xss-protection-http-header.aspx"
	 * >X-XSS-Protection header</a>
	 * </p>
	 * @param xssCustomizer the {@link Customizer} to provide more options for the
	 * {@link XXssConfig}
	 * @return the {@link HeadersConfigurer} for additional customizations
	 */
	public HeadersConfigurer<H> xssProtection(Customizer<XXssConfig> xssCustomizer) {
		xssCustomizer.customize(this.xssProtection.enable());
		return HeadersConfigurer.this;
	}

	/**
	 * Allows customizing the {@link CacheControlHeadersWriter}. Specifically it adds the
	 * following headers:
	 * <ul>
	 * <li>Cache-Control: no-cache, no-store, max-age=0, must-revalidate</li>
	 * <li>Pragma: no-cache</li>
	 * <li>Expires: 0</li>
	 * </ul>
	 * @return the {@link CacheControlConfig} for additional customizations
	 */
	public CacheControlConfig cacheControl() {
		return this.cacheControl.enable();
	}

	/**
	 * Allows customizing the {@link CacheControlHeadersWriter}. Specifically it adds the
	 * following headers:
	 * <ul>
	 * <li>Cache-Control: no-cache, no-store, max-age=0, must-revalidate</li>
	 * <li>Pragma: no-cache</li>
	 * <li>Expires: 0</li>
	 * </ul>
	 * @param cacheControlCustomizer the {@link Customizer} to provide more options for
	 * the {@link CacheControlConfig}
	 * @return the {@link HeadersConfigurer} for additional customizations
	 */
	public HeadersConfigurer<H> cacheControl(Customizer<CacheControlConfig> cacheControlCustomizer) {
		cacheControlCustomizer.customize(this.cacheControl.enable());
		return HeadersConfigurer.this;
	}

	/**
	 * Allows customizing the {@link HstsHeaderWriter} which provides support for
	 * <a href="https://tools.ietf.org/html/rfc6797">HTTP Strict Transport Security
	 * (HSTS)</a>.
	 * @return the {@link HstsConfig} for additional customizations
	 */
	public HstsConfig httpStrictTransportSecurity() {
		return this.hsts.enable();
	}

	/**
	 * Allows customizing the {@link HstsHeaderWriter} which provides support for
	 * <a href="https://tools.ietf.org/html/rfc6797">HTTP Strict Transport Security
	 * (HSTS)</a>.
	 * @param hstsCustomizer the {@link Customizer} to provide more options for the
	 * {@link HstsConfig}
	 * @return the {@link HeadersConfigurer} for additional customizations
	 */
	public HeadersConfigurer<H> httpStrictTransportSecurity(Customizer<HstsConfig> hstsCustomizer) {
		hstsCustomizer.customize(this.hsts.enable());
		return HeadersConfigurer.this;
	}

	/**
	 * Allows customizing the {@link XFrameOptionsHeaderWriter}.
	 * @return the {@link FrameOptionsConfig} for additional customizations
	 */
	public FrameOptionsConfig frameOptions() {
		return this.frameOptions.enable();
	}

	/**
	 * Allows customizing the {@link XFrameOptionsHeaderWriter}.
	 * @param frameOptionsCustomizer the {@link Customizer} to provide more options for
	 * the {@link FrameOptionsConfig}
	 * @return the {@link HeadersConfigurer} for additional customizations
	 */
	public HeadersConfigurer<H> frameOptions(Customizer<FrameOptionsConfig> frameOptionsCustomizer) {
		frameOptionsCustomizer.customize(this.frameOptions.enable());
		return HeadersConfigurer.this;
	}

	/**
	 * Allows customizing the {@link HpkpHeaderWriter} which provides support for
	 * <a href="https://tools.ietf.org/html/rfc7469">HTTP Public Key Pinning (HPKP)</a>.
	 * @return the {@link HpkpConfig} for additional customizations
	 *
	 * @since 4.1
	 * @deprecated see <a href=
	 * "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning">Certificate
	 * and Public Key Pinning</a> for more context
	 */
	@Deprecated
	public HpkpConfig httpPublicKeyPinning() {
		return this.hpkp.enable();
	}

	/**
	 * Allows customizing the {@link HpkpHeaderWriter} which provides support for
	 * <a href="https://tools.ietf.org/html/rfc7469">HTTP Public Key Pinning (HPKP)</a>.
	 * @param hpkpCustomizer the {@link Customizer} to provide more options for the
	 * {@link HpkpConfig}
	 * @return the {@link HeadersConfigurer} for additional customizations
	 * @deprecated see <a href=
	 * "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning">Certificate
	 * and Public Key Pinning</a> for more context
	 */
	@Deprecated
	public HeadersConfigurer<H> httpPublicKeyPinning(Customizer<HpkpConfig> hpkpCustomizer) {
		hpkpCustomizer.customize(this.hpkp.enable());
		return HeadersConfigurer.this;
	}

	/**
	 * <p>
	 * Allows configuration for <a href="https://www.w3.org/TR/CSP2/">Content Security
	 * Policy (CSP) Level 2</a>.
	 * </p>
	 *
	 * <p>
	 * Calling this method automatically enables (includes) the Content-Security-Policy
	 * header in the response using the supplied security policy directive(s).
	 * </p>
	 *
	 * <p>
	 * Configuration is provided to the {@link ContentSecurityPolicyHeaderWriter} which
	 * supports the writing of the two headers as detailed in the W3C Candidate
	 * Recommendation:
	 * </p>
	 * <ul>
	 * <li>Content-Security-Policy</li>
	 * <li>Content-Security-Policy-Report-Only</li>
	 * </ul>
	 * @return the {@link ContentSecurityPolicyConfig} for additional configuration
	 * @throws IllegalArgumentException if policyDirectives is null or empty
	 * @since 4.1
	 * @see ContentSecurityPolicyHeaderWriter
	 */
	public ContentSecurityPolicyConfig contentSecurityPolicy(String policyDirectives) {
		this.contentSecurityPolicy.writer = new ContentSecurityPolicyHeaderWriter(policyDirectives);
		return this.contentSecurityPolicy;
	}

	/**
	 * <p>
	 * Allows configuration for <a href="https://www.w3.org/TR/CSP2/">Content Security
	 * Policy (CSP) Level 2</a>.
	 * </p>
	 *
	 * <p>
	 * Calling this method automatically enables (includes) the Content-Security-Policy
	 * header in the response using the supplied security policy directive(s).
	 * </p>
	 *
	 * <p>
	 * Configuration is provided to the {@link ContentSecurityPolicyHeaderWriter} which
	 * supports the writing of the two headers as detailed in the W3C Candidate
	 * Recommendation:
	 * </p>
	 * <ul>
	 * <li>Content-Security-Policy</li>
	 * <li>Content-Security-Policy-Report-Only</li>
	 * </ul>
	 * @param contentSecurityCustomizer the {@link Customizer} to provide more options for
	 * the {@link ContentSecurityPolicyConfig}
	 * @return the {@link HeadersConfigurer} for additional customizations
	 * @see ContentSecurityPolicyHeaderWriter
	 */
	public HeadersConfigurer<H> contentSecurityPolicy(
			Customizer<ContentSecurityPolicyConfig> contentSecurityCustomizer) {
		this.contentSecurityPolicy.writer = new ContentSecurityPolicyHeaderWriter();
		contentSecurityCustomizer.customize(this.contentSecurityPolicy);
		return HeadersConfigurer.this;
	}

	/**
	 * Clears all of the default headers from the response. After doing so, one can add
	 * headers back. For example, if you only want to use Spring Security's cache control
	 * you can use the following:
	 *
	 * <pre>
	 * http.headers().defaultsDisabled().cacheControl();
	 * </pre>
	 * @return the {@link HeadersConfigurer} for additional customization
	 */
	public HeadersConfigurer<H> defaultsDisabled() {
		this.contentTypeOptions.disable();
		this.xssProtection.disable();
		this.cacheControl.disable();
		this.hsts.disable();
		this.frameOptions.disable();
		return this;
	}

	@Override
	public void configure(H http) {
		HeaderWriterFilter headersFilter = createHeaderWriterFilter();
		http.addFilter(headersFilter);
	}

	/**
	 * Creates the {@link HeaderWriter}
	 * @return the {@link HeaderWriter}
	 */
	private HeaderWriterFilter createHeaderWriterFilter() {
		List<HeaderWriter> writers = getHeaderWriters();
		if (writers.isEmpty()) {
			throw new IllegalStateException(
					"Headers security is enabled, but no headers will be added. Either add headers or disable headers security");
		}
		HeaderWriterFilter headersFilter = new HeaderWriterFilter(writers);
		headersFilter = postProcess(headersFilter);
		return headersFilter;
	}

	/**
	 * Gets the {@link HeaderWriter} instances and possibly initializes with the defaults.
	 * @return
	 */
	private List<HeaderWriter> getHeaderWriters() {
		List<HeaderWriter> writers = new ArrayList<>();
		addIfNotNull(writers, this.contentTypeOptions.writer);
		addIfNotNull(writers, this.xssProtection.writer);
		addIfNotNull(writers, this.cacheControl.writer);
		addIfNotNull(writers, this.hsts.writer);
		addIfNotNull(writers, this.frameOptions.writer);
		addIfNotNull(writers, this.hpkp.writer);
		addIfNotNull(writers, this.contentSecurityPolicy.writer);
		addIfNotNull(writers, this.referrerPolicy.writer);
		addIfNotNull(writers, this.featurePolicy.writer);
		addIfNotNull(writers, this.permissionsPolicy.writer);
		addIfNotNull(writers, this.crossOriginOpenerPolicy.writer);
		addIfNotNull(writers, this.crossOriginEmbedderPolicy.writer);
		addIfNotNull(writers, this.crossOriginResourcePolicy.writer);
		writers.addAll(this.headerWriters);
		return writers;
	}

	private <T> void addIfNotNull(List<T> values, T value) {
		if (value != null) {
			values.add(value);
		}
	}

	/**
	 * <p>
	 * Allows configuration for <a href="https://www.w3.org/TR/referrer-policy/">Referrer
	 * Policy</a>.
	 * </p>
	 *
	 * <p>
	 * Configuration is provided to the {@link ReferrerPolicyHeaderWriter} which support
	 * the writing of the header as detailed in the W3C Technical Report:
	 * </p>
	 * <ul>
	 * <li>Referrer-Policy</li>
	 * </ul>
	 *
	 * <p>
	 * Default value is:
	 * </p>
	 *
	 * <pre>
	 * Referrer-Policy: no-referrer
	 * </pre>
	 * @return the {@link ReferrerPolicyConfig} for additional configuration
	 * @since 4.2
	 * @see ReferrerPolicyHeaderWriter
	 */
	public ReferrerPolicyConfig referrerPolicy() {
		this.referrerPolicy.writer = new ReferrerPolicyHeaderWriter();
		return this.referrerPolicy;
	}

	/**
	 * <p>
	 * Allows configuration for <a href="https://www.w3.org/TR/referrer-policy/">Referrer
	 * Policy</a>.
	 * </p>
	 *
	 * <p>
	 * Configuration is provided to the {@link ReferrerPolicyHeaderWriter} which support
	 * the writing of the header as detailed in the W3C Technical Report:
	 * </p>
	 * <ul>
	 * <li>Referrer-Policy</li>
	 * </ul>
	 * @return the {@link ReferrerPolicyConfig} for additional configuration
	 * @throws IllegalArgumentException if policy is null or empty
	 * @since 4.2
	 * @see ReferrerPolicyHeaderWriter
	 */
	public ReferrerPolicyConfig referrerPolicy(ReferrerPolicy policy) {
		this.referrerPolicy.writer = new ReferrerPolicyHeaderWriter(policy);
		return this.referrerPolicy;
	}

	/**
	 * <p>
	 * Allows configuration for <a href="https://www.w3.org/TR/referrer-policy/">Referrer
	 * Policy</a>.
	 * </p>
	 *
	 * <p>
	 * Configuration is provided to the {@link ReferrerPolicyHeaderWriter} which support
	 * the writing of the header as detailed in the W3C Technical Report:
	 * </p>
	 * <ul>
	 * <li>Referrer-Policy</li>
	 * </ul>
	 * @param referrerPolicyCustomizer the {@link Customizer} to provide more options for
	 * the {@link ReferrerPolicyConfig}
	 * @return the {@link HeadersConfigurer} for additional customizations
	 * @see ReferrerPolicyHeaderWriter
	 */
	public HeadersConfigurer<H> referrerPolicy(Customizer<ReferrerPolicyConfig> referrerPolicyCustomizer) {
		this.referrerPolicy.writer = new ReferrerPolicyHeaderWriter();
		referrerPolicyCustomizer.customize(this.referrerPolicy);
		return HeadersConfigurer.this;
	}

	/**
	 * Allows configuration for <a href="https://wicg.github.io/feature-policy/">Feature
	 * Policy</a>.
	 * <p>
	 * Calling this method automatically enables (includes) the {@code Feature-Policy}
	 * header in the response using the supplied policy directive(s).
	 * <p>
	 * Configuration is provided to the {@link FeaturePolicyHeaderWriter} which is
	 * responsible for writing the header.
	 * @return the {@link FeaturePolicyConfig} for additional configuration
	 * @throws IllegalArgumentException if policyDirectives is {@code null} or empty
	 * @since 5.1
	 * @deprecated Use {@link #permissionsPolicy(Customizer)} instead.
	 * @seeObjectPostProcessorConfiguration FeaturePolicyHeaderWriter
	 */
	@Deprecated
	public FeaturePolicyConfig featurePolicy(String policyDirectives) {
		this.featurePolicy.writer = new FeaturePolicyHeaderWriter(policyDirectives);
		return this.featurePolicy;
	}

	/**
	 * <p>
	 * Allows configuration for
	 * <a href="https://w3c.github.io/webappsec-permissions-policy/">Permissions
	 * Policy</a>.
	 * </p>
	 *
	 * <p>
	 * Configuration is provided to the {@link PermissionsPolicyHeaderWriter} which
	 * support the writing of the header as detailed in the W3C Technical Report:
	 * </p>
	 * <ul>
	 * <li>Permissions-Policy</li>
	 * </ul>
	 * @return the {@link PermissionsPolicyConfig} for additional configuration
	 * @since 5.5
	 * @see PermissionsPolicyHeaderWriter
	 */
	public PermissionsPolicyConfig permissionsPolicy() {
		this.permissionsPolicy.writer = new PermissionsPolicyHeaderWriter();
		return this.permissionsPolicy;
	}

	/**
	 * Allows configuration for
	 * <a href="https://w3c.github.io/webappsec-permissions-policy/"> Permissions
	 * Policy</a>.
	 * <p>
	 * Calling this method automatically enables (includes) the {@code Permissions-Policy}
	 * header in the response using the supplied policy directive(s).
	 * <p>
	 * Configuration is provided to the {@link PermissionsPolicyHeaderWriter} which is
	 * responsible for writing the header.
	 * @return the {@link PermissionsPolicyConfig} for additional configuration
	 * @throws IllegalArgumentException if policyDirectives is {@code null} or empty
	 * @since 5.5
	 * @see PermissionsPolicyHeaderWriter
	 */
	public PermissionsPolicyConfig permissionsPolicy(Customizer<PermissionsPolicyConfig> permissionsPolicyCustomizer) {
		this.permissionsPolicy.writer = new PermissionsPolicyHeaderWriter();
		permissionsPolicyCustomizer.customize(this.permissionsPolicy);
		return this.permissionsPolicy;
	}

	/**
	 * Allows configuration for <a href=
	 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy">
	 * Cross-Origin-Opener-Policy</a> header.
	 * <p>
	 * Configuration is provided to the {@link CrossOriginOpenerPolicyHeaderWriter} which
	 * responsible for writing the header.
	 * </p>
	 * @return the {@link CrossOriginOpenerPolicyConfig} for additional confniguration
	 * @since 5.7
	 * @see CrossOriginOpenerPolicyHeaderWriter
	 */
	public CrossOriginOpenerPolicyConfig crossOriginOpenerPolicy() {
		this.crossOriginOpenerPolicy.writer = new CrossOriginOpenerPolicyHeaderWriter();
		return this.crossOriginOpenerPolicy;
	}

	/**
	 * Allows configuration for <a href=
	 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy">
	 * Cross-Origin-Opener-Policy</a> header.
	 * <p>
	 * Calling this method automatically enables (includes) the
	 * {@code Cross-Origin-Opener-Policy} header in the response using the supplied
	 * policy.
	 * <p>
	 * <p>
	 * Configuration is provided to the {@link CrossOriginOpenerPolicyHeaderWriter} which
	 * responsible for writing the header.
	 * </p>
	 * @return the {@link HeadersConfigurer} for additional customizations
	 * @since 5.7
	 * @see CrossOriginOpenerPolicyHeaderWriter
	 */
	public HeadersConfigurer<H> crossOriginOpenerPolicy(
			Customizer<CrossOriginOpenerPolicyConfig> crossOriginOpenerPolicyCustomizer) {
		this.crossOriginOpenerPolicy.writer = new CrossOriginOpenerPolicyHeaderWriter();
		crossOriginOpenerPolicyCustomizer.customize(this.crossOriginOpenerPolicy);
		return HeadersConfigurer.this;
	}

	/**
	 * Allows configuration for <a href=
	 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy">
	 * Cross-Origin-Embedder-Policy</a> header.
	 * <p>
	 * Configuration is provided to the {@link CrossOriginEmbedderPolicyHeaderWriter}
	 * which is responsible for writing the header.
	 * </p>
	 * @return the {@link CrossOriginEmbedderPolicyConfig} for additional customizations
	 * @since 5.7
	 * @see CrossOriginEmbedderPolicyHeaderWriter
	 */
	public CrossOriginEmbedderPolicyConfig crossOriginEmbedderPolicy() {
		this.crossOriginEmbedderPolicy.writer = new CrossOriginEmbedderPolicyHeaderWriter();
		return this.crossOriginEmbedderPolicy;
	}

	/**
	 * Allows configuration for <a href=
	 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy">
	 * Cross-Origin-Embedder-Policy</a> header.
	 * <p>
	 * Calling this method automatically enables (includes) the
	 * {@code Cross-Origin-Embedder-Policy} header in the response using the supplied
	 * policy.
	 * <p>
	 * <p>
	 * Configuration is provided to the {@link CrossOriginEmbedderPolicyHeaderWriter}
	 * which is responsible for writing the header.
	 * </p>
	 * @return the {@link HeadersConfigurer} for additional customizations
	 * @since 5.7
	 * @see CrossOriginEmbedderPolicyHeaderWriter
	 */
	public HeadersConfigurer<H> crossOriginEmbedderPolicy(
			Customizer<CrossOriginEmbedderPolicyConfig> crossOriginEmbedderPolicyCustomizer) {
		this.crossOriginEmbedderPolicy.writer = new CrossOriginEmbedderPolicyHeaderWriter();
		crossOriginEmbedderPolicyCustomizer.customize(this.crossOriginEmbedderPolicy);
		return HeadersConfigurer.this;
	}

	/**
	 * Allows configuration for <a href=
	 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy">
	 * Cross-Origin-Resource-Policy</a> header.
	 * <p>
	 * Configuration is provided to the {@link CrossOriginResourcePolicyHeaderWriter}
	 * which is responsible for writing the header:
	 * </p>
	 * @return the {@link HeadersConfigurer} for additional customizations
	 * @since 5.7
	 * @see CrossOriginResourcePolicyHeaderWriter
	 */
	public CrossOriginResourcePolicyConfig crossOriginResourcePolicy() {
		this.crossOriginResourcePolicy.writer = new CrossOriginResourcePolicyHeaderWriter();
		return this.crossOriginResourcePolicy;
	}

	/**
	 * Allows configuration for <a href=
	 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Resource-Policy">
	 * Cross-Origin-Resource-Policy</a> header.
	 * <p>
	 * Calling this method automatically enables (includes) the
	 * {@code Cross-Origin-Resource-Policy} header in the response using the supplied
	 * policy.
	 * <p>
	 * <p>
	 * Configuration is provided to the {@link CrossOriginResourcePolicyHeaderWriter}
	 * which is responsible for writing the header:
	 * </p>
	 * @return the {@link HeadersConfigurer} for additional customizations
	 * @since 5.7
	 * @see CrossOriginResourcePolicyHeaderWriter
	 */
	public HeadersConfigurer<H> crossOriginResourcePolicy(
			Customizer<CrossOriginResourcePolicyConfig> crossOriginResourcePolicyCustomizer) {
		this.crossOriginResourcePolicy.writer = new CrossOriginResourcePolicyHeaderWriter();
		crossOriginResourcePolicyCustomizer.customize(this.crossOriginResourcePolicy);
		return HeadersConfigurer.this;
	}

	public final class ContentTypeOptionsConfig {

		private XContentTypeOptionsHeaderWriter writer;

		private ContentTypeOptionsConfig() {
			enable();
		}

		/**
		 * Removes the X-XSS-Protection header.
		 * @return {@link HeadersConfigurer} for additional customization.
		 */
		public HeadersConfigurer<H> disable() {
			this.writer = null;
			return and();
		}

		/**
		 * Allows customizing the {@link HeadersConfigurer}
		 * @return the {@link HeadersConfigurer} for additional customization
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

		/**
		 * Ensures that Content Type Options is enabled
		 * @return the {@link ContentTypeOptionsConfig} for additional customization
		 */
		private ContentTypeOptionsConfig enable() {
			if (this.writer == null) {
				this.writer = new XContentTypeOptionsHeaderWriter();
			}
			return this;
		}

	}

	public final class XXssConfig {

		private XXssProtectionHeaderWriter writer;

		private XXssConfig() {
			enable();
		}

		/**
		 * Sets the value of the X-XSS-PROTECTION header. OWASP recommends using
		 * {@link XXssProtectionHeaderWriter.HeaderValue#DISABLED}.
		 *
		 * If {@link XXssProtectionHeaderWriter.HeaderValue#DISABLED}, will specify that
		 * X-XSS-Protection is disabled. For example:
		 *
		 * <pre>
		 * X-XSS-Protection: 0
		 * </pre>
		 *
		 * If {@link XXssProtectionHeaderWriter.HeaderValue#ENABLED}, will contain a value
		 * of 1, but will not specify the mode as blocked. In this instance, any content
		 * will be attempted to be fixed. For example:
		 *
		 * <pre>
		 * X-XSS-Protection: 1
		 * </pre>
		 *
		 * If {@link XXssProtectionHeaderWriter.HeaderValue#ENABLED_MODE_BLOCK}, will
		 * contain a value of 1 and will specify mode as blocked. The content will be
		 * replaced with "#". For example:
		 *
		 * <pre>
		 * X-XSS-Protection: 1 ; mode=block
		 * </pre>
		 * @param headerValue the new header value
		 * @since 5.8
		 */
		public XXssConfig headerValue(XXssProtectionHeaderWriter.HeaderValue headerValue) {
			this.writer.setHeaderValue(headerValue);
			return this;
		}

		/**
		 * Disables X-XSS-Protection header (does not include it)
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> disable() {
			this.writer = null;
			return and();
		}

		/**
		 * Allows completing configuration of X-XSS-Protection and continuing
		 * configuration of headers.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

		/**
		 * Ensures the X-XSS-Protection header is enabled if it is not already.
		 * @return the {@link XXssConfig} for additional customization
		 */
		private XXssConfig enable() {
			if (this.writer == null) {
				this.writer = new XXssProtectionHeaderWriter();
			}
			return this;
		}

	}

	public final class CacheControlConfig {

		private CacheControlHeadersWriter writer;

		private CacheControlConfig() {
			enable();
		}

		/**
		 * Disables Cache Control
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> disable() {
			this.writer = null;
			return HeadersConfigurer.this;
		}

		/**
		 * Allows completing configuration of Cache Control and continuing configuration
		 * of headers.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

		/**
		 * Ensures the Cache Control headers are enabled if they are not already.
		 * @return the {@link CacheControlConfig} for additional customization
		 */
		private CacheControlConfig enable() {
			if (this.writer == null) {
				this.writer = new CacheControlHeadersWriter();
			}
			return this;
		}

	}

	public final class HstsConfig {

		private HstsHeaderWriter writer;

		private HstsConfig() {
			enable();
		}

		/**
		 * <p>
		 * Sets the value (in seconds) for the max-age directive of the
		 * Strict-Transport-Security header. The default is one year.
		 * </p>
		 *
		 * <p>
		 * This instructs browsers how long to remember to keep this domain as a known
		 * HSTS Host. See
		 * <a href="https://tools.ietf.org/html/rfc6797#section-6.1.1">Section 6.1.1</a>
		 * for additional details.
		 * </p>
		 * @param maxAgeInSeconds the maximum amount of time (in seconds) to consider this
		 * domain as a known HSTS Host.
		 * @throws IllegalArgumentException if maxAgeInSeconds is negative
		 */
		public HstsConfig maxAgeInSeconds(long maxAgeInSeconds) {
			this.writer.setMaxAgeInSeconds(maxAgeInSeconds);
			return this;
		}

		/**
		 * Sets the {@link RequestMatcher} used to determine if the
		 * "Strict-Transport-Security" should be added. If true the header is added, else
		 * the header is not added. By default the header is added when
		 * {@link HttpServletRequest#isSecure()} returns true.
		 * @param requestMatcher the {@link RequestMatcher} to use.
		 * @throws IllegalArgumentException if {@link RequestMatcher} is null
		 */
		public HstsConfig requestMatcher(RequestMatcher requestMatcher) {
			this.writer.setRequestMatcher(requestMatcher);
			return this;
		}

		/**
		 * <p>
		 * If true, subdomains should be considered HSTS Hosts too. The default is true.
		 * </p>
		 *
		 * <p>
		 * See <a href="https://tools.ietf.org/html/rfc6797#section-6.1.2">Section
		 * 6.1.2</a> for additional details.
		 * </p>
		 * @param includeSubDomains true to include subdomains, else false
		 */
		public HstsConfig includeSubDomains(boolean includeSubDomains) {
			this.writer.setIncludeSubDomains(includeSubDomains);
			return this;
		}

		/**
		 * <p>
		 * If true, preload will be included in HSTS Header. The default is false.
		 * </p>
		 *
		 * <p>
		 * See <a href="https://hstspreload.org/">Website hstspreload.org</a> for
		 * additional details.
		 * </p>
		 * @param preload true to include preload, else false
		 * @since 5.2.0
		 */
		public HstsConfig preload(boolean preload) {
			this.writer.setPreload(preload);
			return this;
		}

		/**
		 * Disables Strict Transport Security
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> disable() {
			this.writer = null;
			return HeadersConfigurer.this;
		}

		/**
		 * Allows completing configuration of Strict Transport Security and continuing
		 * configuration of headers.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

		/**
		 * Ensures that Strict-Transport-Security is enabled if it is not already
		 * @return the {@link HstsConfig} for additional customization
		 */
		private HstsConfig enable() {
			if (this.writer == null) {
				this.writer = new HstsHeaderWriter();
			}
			return this;
		}

	}

	public final class FrameOptionsConfig {

		private XFrameOptionsHeaderWriter writer;

		private FrameOptionsConfig() {
			enable();
		}

		/**
		 * Specify to DENY framing any content from this application.
		 * @return the {@link HeadersConfigurer} for additional customization.
		 */
		public HeadersConfigurer<H> deny() {
			this.writer = new XFrameOptionsHeaderWriter(XFrameOptionsMode.DENY);
			return and();
		}

		/**
		 * <p>
		 * Specify to allow any request that comes from the same origin to frame this
		 * application. For example, if the application was hosted on example.com, then
		 * example.com could frame the application, but evil.com could not frame the
		 * application.
		 * </p>
		 * @return the {@link HeadersConfigurer} for additional customization.
		 */
		public HeadersConfigurer<H> sameOrigin() {
			this.writer = new XFrameOptionsHeaderWriter(XFrameOptionsMode.SAMEORIGIN);
			return and();
		}

		/**
		 * Prevents the header from being added to the response.
		 * @return the {@link HeadersConfigurer} for additional configuration.
		 */
		public HeadersConfigurer<H> disable() {
			this.writer = null;
			return and();
		}

		/**
		 * Allows continuing customizing the headers configuration.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

		/**
		 * Enables FrameOptionsConfig if it is not already enabled.
		 * @return the FrameOptionsConfig for additional customization.
		 */
		private FrameOptionsConfig enable() {
			if (this.writer == null) {
				this.writer = new XFrameOptionsHeaderWriter(XFrameOptionsMode.DENY);
			}
			return this;
		}

	}

	/**
	 * @deprecated see <a href=
	 * "https://owasp.org/www-community/controls/Certificate_and_Public_Key_Pinning">Certificate
	 * and Public Key Pinning</a> for more context
	 */
	@Deprecated
	public final class HpkpConfig {

		private HpkpHeaderWriter writer;

		private HpkpConfig() {
		}

		/**
		 * <p>
		 * Sets the value for the pin- directive of the Public-Key-Pins header.
		 * </p>
		 *
		 * <p>
		 * The pin directive specifies a way for web host operators to indicate a
		 * cryptographic identity that should be bound to a given web host. See
		 * <a href="https://tools.ietf.org/html/rfc7469#section-2.1.1">Section 2.1.1</a>
		 * for additional details.
		 * </p>
		 * @param pins the map of base64-encoded SPKI fingerprint &amp; cryptographic hash
		 * algorithm pairs.
		 * @throws IllegalArgumentException if pins is null
		 */
		public HpkpConfig withPins(Map<String, String> pins) {
			this.writer.setPins(pins);
			return this;
		}

		/**
		 * <p>
		 * Adds a list of SHA256 hashed pins for the pin- directive of the Public-Key-Pins
		 * header.
		 * </p>
		 *
		 * <p>
		 * The pin directive specifies a way for web host operators to indicate a
		 * cryptographic identity that should be bound to a given web host. See
		 * <a href="https://tools.ietf.org/html/rfc7469#section-2.1.1">Section 2.1.1</a>
		 * for additional details.
		 * </p>
		 * @param pins a list of base64-encoded SPKI fingerprints.
		 * @throws IllegalArgumentException if a pin is null
		 */
		public HpkpConfig addSha256Pins(String... pins) {
			this.writer.addSha256Pins(pins);
			return this;
		}

		/**
		 * <p>
		 * Sets the value (in seconds) for the max-age directive of the Public-Key-Pins
		 * header. The default is 60 days.
		 * </p>
		 *
		 * <p>
		 * This instructs browsers how long they should regard the host (from whom the
		 * message was received) as a known pinned host. See
		 * <a href="https://tools.ietf.org/html/rfc7469#section-2.1.2">Section 2.1.2</a>
		 * for additional details.
		 * </p>
		 * @param maxAgeInSeconds the maximum amount of time (in seconds) to regard the
		 * host as a known pinned host.
		 * @throws IllegalArgumentException if maxAgeInSeconds is negative
		 */
		public HpkpConfig maxAgeInSeconds(long maxAgeInSeconds) {
			this.writer.setMaxAgeInSeconds(maxAgeInSeconds);
			return this;
		}

		/**
		 * <p>
		 * If true, the pinning policy applies to this pinned host as well as any
		 * subdomains of the host's domain name. The default is false.
		 * </p>
		 *
		 * <p>
		 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.3">Section
		 * 2.1.3</a> for additional details.
		 * </p>
		 * @param includeSubDomains true to include subdomains, else false
		 */
		public HpkpConfig includeSubDomains(boolean includeSubDomains) {
			this.writer.setIncludeSubDomains(includeSubDomains);
			return this;
		}

		/**
		 * <p>
		 * If true, the browser should not terminate the connection with the server. The
		 * default is true.
		 * </p>
		 *
		 * <p>
		 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1">Section 2.1</a>
		 * for additional details.
		 * </p>
		 * @param reportOnly true to report only, else false
		 */
		public HpkpConfig reportOnly(boolean reportOnly) {
			this.writer.setReportOnly(reportOnly);
			return this;
		}

		/**
		 * <p>
		 * Sets the URI to which the browser should report pin validation failures.
		 * </p>
		 *
		 * <p>
		 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.4">Section
		 * 2.1.4</a> for additional details.
		 * </p>
		 * @param reportUri the URI where the browser should send the report to.
		 */
		public HpkpConfig reportUri(URI reportUri) {
			this.writer.setReportUri(reportUri);
			return this;
		}

		/**
		 * <p>
		 * Sets the URI to which the browser should report pin validation failures.
		 * </p>
		 *
		 * <p>
		 * See <a href="https://tools.ietf.org/html/rfc7469#section-2.1.4">Section
		 * 2.1.4</a> for additional details.
		 * </p>
		 * @param reportUri the URI where the browser should send the report to.
		 * @throws IllegalArgumentException if the reportUri is not a valid URI
		 */
		public HpkpConfig reportUri(String reportUri) {
			this.writer.setReportUri(reportUri);
			return this;
		}

		/**
		 * Prevents the header from being added to the response.
		 * @return the {@link HeadersConfigurer} for additional configuration.
		 */
		public HeadersConfigurer<H> disable() {
			this.writer = null;
			return and();
		}

		/**
		 * Allows completing configuration of Public Key Pinning and continuing
		 * configuration of headers.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

		/**
		 * Ensures that Public-Key-Pins or Public-Key-Pins-Report-Only is enabled if it is
		 * not already
		 * @return the {@link HstsConfig} for additional customization
		 */
		private HpkpConfig enable() {
			if (this.writer == null) {
				this.writer = new HpkpHeaderWriter();
			}
			return this;
		}

	}

	public final class ContentSecurityPolicyConfig {

		private ContentSecurityPolicyHeaderWriter writer;

		private ContentSecurityPolicyConfig() {
		}

		/**
		 * Sets the security policy directive(s) to be used in the response header.
		 * @param policyDirectives the security policy directive(s)
		 * @return the {@link ContentSecurityPolicyConfig} for additional configuration
		 * @throws IllegalArgumentException if policyDirectives is null or empty
		 */
		public ContentSecurityPolicyConfig policyDirectives(String policyDirectives) {
			this.writer.setPolicyDirectives(policyDirectives);
			return this;
		}

		/**
		 * Enables (includes) the Content-Security-Policy-Report-Only header in the
		 * response.
		 * @return the {@link ContentSecurityPolicyConfig} for additional configuration
		 */
		public ContentSecurityPolicyConfig reportOnly() {
			this.writer.setReportOnly(true);
			return this;
		}

		/**
		 * Allows completing configuration of Content Security Policy and continuing
		 * configuration of headers.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

	}

	public final class ReferrerPolicyConfig {

		private ReferrerPolicyHeaderWriter writer;

		private ReferrerPolicyConfig() {
		}

		/**
		 * Sets the policy to be used in the response header.
		 * @param policy a referrer policy
		 * @return the {@link ReferrerPolicyConfig} for additional configuration
		 * @throws IllegalArgumentException if policy is null
		 */
		public ReferrerPolicyConfig policy(ReferrerPolicy policy) {
			this.writer.setPolicy(policy);
			return this;
		}

		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

	}

	public final class FeaturePolicyConfig {

		private FeaturePolicyHeaderWriter writer;

		private FeaturePolicyConfig() {
		}

		/**
		 * Allows completing configuration of Feature Policy and continuing configuration
		 * of headers.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

	}

	public final class PermissionsPolicyConfig {

		private PermissionsPolicyHeaderWriter writer;

		private PermissionsPolicyConfig() {
		}

		/**
		 * Sets the policy to be used in the response header.
		 * @param policy a permissions policy
		 * @return the {@link PermissionsPolicyConfig} for additional configuration
		 * @throws IllegalArgumentException if policy is null
		 */
		public PermissionsPolicyConfig policy(String policy) {
			this.writer.setPolicy(policy);
			return this;
		}

		/**
		 * Allows completing configuration of Permissions Policy and continuing
		 * configuration of headers.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

	}

	public final class CrossOriginOpenerPolicyConfig {

		private CrossOriginOpenerPolicyHeaderWriter writer;

		public CrossOriginOpenerPolicyConfig() {
		}

		/**
		 * Sets the policy to be used in the {@code Cross-Origin-Opener-Policy} header
		 * @param openerPolicy a {@code Cross-Origin-Opener-Policy}
		 * @return the {@link CrossOriginOpenerPolicyConfig} for additional configuration
		 * @throws IllegalArgumentException if openerPolicy is null
		 */
		public CrossOriginOpenerPolicyConfig policy(
				CrossOriginOpenerPolicyHeaderWriter.CrossOriginOpenerPolicy openerPolicy) {
			this.writer.setPolicy(openerPolicy);
			return this;
		}

		/**
		 * Allows completing configuration of Cross Origin Opener Policy and continuing
		 * configuration of headers.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

	}

	public final class CrossOriginEmbedderPolicyConfig {

		private CrossOriginEmbedderPolicyHeaderWriter writer;

		public CrossOriginEmbedderPolicyConfig() {
		}

		/**
		 * Sets the policy to be used in the {@code Cross-Origin-Embedder-Policy} header
		 * @param embedderPolicy a {@code Cross-Origin-Embedder-Policy}
		 * @return the {@link CrossOriginEmbedderPolicyConfig} for additional
		 * configuration
		 * @throws IllegalArgumentException if embedderPolicy is null
		 */
		public CrossOriginEmbedderPolicyConfig policy(
				CrossOriginEmbedderPolicyHeaderWriter.CrossOriginEmbedderPolicy embedderPolicy) {
			this.writer.setPolicy(embedderPolicy);
			return this;
		}

		/**
		 * Allows completing configuration of Cross-Origin-Embedder-Policy and continuing
		 * configuration of headers.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

	}

	public final class CrossOriginResourcePolicyConfig {

		private CrossOriginResourcePolicyHeaderWriter writer;

		public CrossOriginResourcePolicyConfig() {
		}

		/**
		 * Sets the policy to be used in the {@code Cross-Origin-Resource-Policy} header
		 * @param resourcePolicy a {@code Cross-Origin-Resource-Policy}
		 * @return the {@link CrossOriginResourcePolicyConfig} for additional
		 * configuration
		 * @throws IllegalArgumentException if resourcePolicy is null
		 */
		public CrossOriginResourcePolicyConfig policy(
				CrossOriginResourcePolicyHeaderWriter.CrossOriginResourcePolicy resourcePolicy) {
			this.writer.setPolicy(resourcePolicy);
			return this;
		}

		/**
		 * Allows completing configuration of Cross-Origin-Resource-Policy and continuing
		 * configuration of headers.
		 * @return the {@link HeadersConfigurer} for additional configuration
		 */
		public HeadersConfigurer<H> and() {
			return HeadersConfigurer.this;
		}

	}

}
