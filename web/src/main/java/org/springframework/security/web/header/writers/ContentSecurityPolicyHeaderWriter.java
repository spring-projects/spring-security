/*
 * Copyright 2002-2019 the original author or authors.
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

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * <p>
 * Provides support for <a href="https://www.w3.org/TR/CSP2/">Content Security Policy (CSP) Level 2</a>.
 * </p>
 *
 * <p>
 * CSP provides a mechanism for web applications to mitigate content injection vulnerabilities,
 * such as cross-site scripting (XSS). CSP is a declarative policy that allows web application authors to inform
 * the client (user-agent) about the sources from which the application expects to load resources.
 * </p>
 *
 * <p>
 * For example, a web application can declare that it only expects to load script from specific, trusted sources.
 * This declaration allows the client to detect and block malicious scripts injected into the application by an attacker.
 * </p>
 *
 * <p>
 * A declaration of a security policy contains a set of security policy directives (for example, script-src and object-src),
 * each responsible for declaring the restrictions for a particular resource type.
 * The list of directives defined can be found at
 * <a href="https://www.w3.org/TR/CSP2/#directives">Directives</a>.
 * </p>
 *
 * <p>
 * Each directive has a name and value. For detailed syntax on writing security policies, see
 * <a href="https://www.w3.org/TR/CSP2/#syntax-and-algorithms">Syntax and Algorithms</a>.
 * </p>
 *
 * <p>
 * This implementation of {@link HeaderWriter} writes one of the following headers:
 * </p>
 * <ul>
 * 	<li>Content-Security-Policy</li>
 * 	<li>Content-Security-Policy-Report-Only</li>
 * </ul>
 *
 * <p>
 * By default, the Content-Security-Policy header is included in the response.
 * However, calling {@link #setReportOnly(boolean)} with {@code true} will include the
 * Content-Security-Policy-Report-Only header in the response.
 * <strong>NOTE:</strong> The supplied security policy directive(s) will be used for whichever header is enabled (included).
 * </p>
 *
 * <p>
 * <strong>
 * CSP is not intended as a first line of defense against content injection vulnerabilities.
 * Instead, CSP is used to reduce the harm caused by content injection attacks.
 * As a first line of defense against content injection, web application authors should validate their input and encode their output.
 * </strong>
 * </p>
 *
 * @author Joe Grandja
 * @author Ankur Pathak
 * @since 4.1
 */
public final class ContentSecurityPolicyHeaderWriter implements HeaderWriter {
	private static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";

	private static final String CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";

	private String policyDirectives;

	private boolean reportOnly;

	/**
	 * Creates a new instance
	 *
	 * @param policyDirectives maps to {@link #setPolicyDirectives(String)}
	 * @throws IllegalArgumentException if policyDirectives is null or empty
	 */
	public ContentSecurityPolicyHeaderWriter(String policyDirectives) {
		setPolicyDirectives(policyDirectives);
		this.reportOnly = false;
	}

	/**
	 * @see org.springframework.security.web.header.HeaderWriter#writeHeaders(javax.servlet.http.HttpServletRequest, javax.servlet.http.HttpServletResponse)
	 */
	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		String headerName = !reportOnly ? CONTENT_SECURITY_POLICY_HEADER : CONTENT_SECURITY_POLICY_REPORT_ONLY_HEADER;
		if (!response.containsHeader(headerName)) {
			response.setHeader(headerName, policyDirectives);
		}
	}

	/**
	 * Sets the security policy directive(s) to be used in the response header.
	 *
	 * @param policyDirectives the security policy directive(s)
	 * @throws IllegalArgumentException if policyDirectives is null or empty
	 */
	public void setPolicyDirectives(String policyDirectives) {
		Assert.hasLength(policyDirectives, "policyDirectives cannot be null or empty");
		this.policyDirectives = policyDirectives;
	}

	/**
	 * If true, includes the Content-Security-Policy-Report-Only header in the response,
	 * otherwise, defaults to the Content-Security-Policy header.

	 * @param reportOnly set to true for reporting policy violations only
	 */
	public void setReportOnly(boolean reportOnly) {
		this.reportOnly = reportOnly;
	}

	@Override
	public String toString() {
		return getClass().getName() + " [policyDirectives=" + policyDirectives + "; reportOnly=" + reportOnly + "]";
	}

}
