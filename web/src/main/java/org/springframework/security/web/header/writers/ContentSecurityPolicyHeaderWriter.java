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

package org.springframework.security.web.header.writers;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

/**
 * <p>
 * Provides support for <a href="https://www.w3.org/TR/CSP2/">Content Security Policy
 * (CSP) Level 2</a>.
 * </p>
 *
 * <p>
 * CSP provides a mechanism for web applications to mitigate content injection
 * vulnerabilities, such as cross-site scripting (XSS). CSP is a declarative policy that
 * allows web application authors to inform the client (user-agent) about the sources from
 * which the application expects to load resources.
 * </p>
 *
 * <p>
 * For example, a web application can declare that it only expects to load script from
 * specific, trusted sources. This declaration allows the client to detect and block
 * malicious scripts injected into the application by an attacker.
 * </p>
 *
 * <p>
 * A declaration of a security policy contains a set of security policy directives (for
 * example, script-src and object-src), each responsible for declaring the restrictions
 * for a particular resource type. The list of directives defined can be found at
 * <a href="https://www.w3.org/TR/CSP2/#directives">Directives</a>.
 * </p>
 *
 * <p>
 * Each directive has a name and value. For detailed syntax on writing security policies,
 * see <a href="https://www.w3.org/TR/CSP2/#syntax-and-algorithms">Syntax and
 * Algorithms</a>.
 * </p>
 *
 * <p>
 * With related directives specified, web clients could block inline {@code <script>} or
 * {@code <style>} blocks in the HTML to mitigate XSS attacks injecting malicious inline
 * blocks. To allow intended inline blocks, a CSP directive (usually {@code script-src} or
 * {@code style-src}) may specify a hard-to-guess nonce matching the nonce attributes of
 * inline HTML blocks.
 * </p>
 *
 * <p>
 * To ease writing nonce-based CSP headers, this class replaces the {@code {nonce}}
 * placeholder in the {@code policyDirectives} with a real nonce value read from a servlet
 * request attribute named {@code _csp_nonce} (or another configured attribute name). A
 * {@link org.springframework.security.web.header.NonceGeneratingFilter} can be configured
 * to generate a unique secure random {@code _csp_nonce} attribute for each request.
 * </p>
 *
 * <p>
 * For example, if the configured {@code policyDirectives} is {@code script-src 'self'
 * 'nonce-{nonce}'}, and a
 * {@link org.springframework.security.web.header.NonceGeneratingFilter} has set the
 * {@code _csp_nonce} attribute to {@code "Nc3n83cnSAd3wc3Sasdfn9"}, then the written HTTP
 * header value would be {@code script-src 'self' 'nonce-Nc3n83cnSAd3wc3Sasdfn9'}.
 * </p>
 *
 * <p>
 * This implementation of {@link HeaderWriter} writes one of the following headers:
 * </p>
 * <ul>
 * <li>Content-Security-Policy</li>
 * <li>Content-Security-Policy-Report-Only</li>
 * </ul>
 *
 * <p>
 * By default, the Content-Security-Policy header is included in the response. However,
 * calling {@link #setReportOnly(boolean)} with {@code true} will include the
 * Content-Security-Policy-Report-Only header in the response. <strong>NOTE:</strong> The
 * supplied security policy directive(s) will be used for whichever header is enabled
 * (included).
 * </p>
 *
 * <p>
 * <strong> CSP is not intended as a first line of defense against content injection
 * vulnerabilities. Instead, CSP is used to reduce the harm caused by content injection
 * attacks. As a first line of defense against content injection, web application authors
 * should validate their input and encode their output. </strong>
 * </p>
 *
 * @author Joe Grandja
 * @author Ankur Pathak
 * @author Ziqin Wang
 * @since 4.1
 * @see org.springframework.security.web.header.NonceGeneratingFilter
 */
public final class ContentSecurityPolicyHeaderWriter implements HeaderWriter {

	public static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";

	public static final String CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";

	private static final String DEFAULT_SRC_SELF_POLICY = "default-src 'self'";

	public static final String DEFAULT_NONCE_ATTRIBUTE_NAME = "_csp_nonce";

	public static final String NONCE_PLACEHOLDER = "{nonce}";

	private String policyDirectives;

	private boolean reportOnly;

	private boolean isNonceBased;

	private String nonceAttributeName = DEFAULT_NONCE_ATTRIBUTE_NAME;

	/**
	 * Creates a new instance. Default value: default-src 'self'
	 */
	public ContentSecurityPolicyHeaderWriter() {
		setPolicyDirectives(DEFAULT_SRC_SELF_POLICY);
		this.reportOnly = false;
	}

	/**
	 * Creates a new instance
	 * @param policyDirectives maps to {@link #setPolicyDirectives(String)}
	 * @throws IllegalArgumentException if policyDirectives is null or empty
	 */
	public ContentSecurityPolicyHeaderWriter(String policyDirectives) {
		setPolicyDirectives(policyDirectives);
		this.reportOnly = false;
	}

	/**
	 * @see org.springframework.security.web.header.HeaderWriter#writeHeaders(jakarta.servlet.http.HttpServletRequest,
	 * jakarta.servlet.http.HttpServletResponse)
	 */
	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		String headerName = (!this.reportOnly) ? CONTENT_SECURITY_POLICY_HEADER
				: CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER;
		if (!response.containsHeader(headerName)) {
			String csp;
			if (this.isNonceBased) {
				String nonce = (String) request.getAttribute(this.nonceAttributeName);
				Assert.state(nonce != null, "Nonce is unset");
				csp = this.policyDirectives.replace(NONCE_PLACEHOLDER, nonce);
			}
			else {
				csp = this.policyDirectives;
			}
			response.setHeader(headerName, csp);
		}
	}

	/**
	 * Sets the security policy directive(s) to be used in the response header. The
	 * {@code policyDirectives} may contain {@code {nonce}} as placeholders to be
	 * replaced.
	 * @param policyDirectives the security policy directive(s)
	 * @throws IllegalArgumentException if policyDirectives is null or empty
	 */
	public void setPolicyDirectives(String policyDirectives) {
		Assert.hasLength(policyDirectives, "policyDirectives cannot be null or empty");
		this.policyDirectives = policyDirectives;
		this.isNonceBased = policyDirectives.contains(NONCE_PLACEHOLDER);
	}

	/**
	 * If true, includes the Content-Security-Policy-Report-Only header in the response,
	 * otherwise, defaults to the Content-Security-Policy header.
	 * @param reportOnly set to true for reporting policy violations only
	 */
	public void setReportOnly(boolean reportOnly) {
		this.reportOnly = reportOnly;
	}

	/**
	 * Sets the name of the servlet request attribute from which the nonce value is taken.
	 * Defaults to {@code _csp_nonce} if unset.
	 * @param nonceAttributeName the name of the nonce attribute
	 * @throws IllegalArgumentException if {@code nonceAttributeName} is {@code null} or
	 * empty
	 * @since 7.1
	 */
	public void setNonceAttributeName(String nonceAttributeName) {
		Assert.hasLength(nonceAttributeName, "nonceAttributeName cannot be null or empty");
		this.nonceAttributeName = nonceAttributeName;
	}

	/**
	 * Returns the name of the servlet request attribute from which the nonce value is
	 * taken. Defaults to {@code _csp_nonce} if unset.
	 * @return the name of the nonce attribute.
	 * @since 7.1
	 */
	public String getNonceAttributeName() {
		return this.nonceAttributeName;
	}

	/**
	 * Returns whether the content security policy is nonce-based. The CSP is considered
	 * nonce-based if the configured {@code policyDirectives} string contains a
	 * {@code {nonce}} placeholder.
	 * @return whether the content security policy is nonce-based
	 * @since 7.1
	 */
	public boolean isNonceBased() {
		return this.isNonceBased;
	}

	@Override
	public String toString() {
		return getClass().getName() + " [policyDirectives=" + this.policyDirectives + "; reportOnly=" + this.reportOnly
				+ "; isNonceBased=" + this.isNonceBased + "; nonceAttributeName=" + this.nonceAttributeName + "]";
	}

}
