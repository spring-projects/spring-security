/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.header.writers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

/**
 * Provides support for <a href="https://wicg.github.io/feature-policy/">Feature
 * Policy</a>.
 * <p>
 * Feature Policy allows web developers to selectively enable, disable, and modify the
 * behavior of certain APIs and web features in the browser.
 * <p>
 * A declaration of a feature policy contains a set of security policy directives, each
 * responsible for declaring the restrictions for a particular feature type.
 *
 * @author Vedran Pavic
 * @author Ankur Pathak
 * @since 5.1
 */
public final class FeaturePolicyHeaderWriter implements HeaderWriter {

	private static final String FEATURE_POLICY_HEADER = "Feature-Policy";

	private String policyDirectives;

	/**
	 * Create a new instance of {@link FeaturePolicyHeaderWriter} with supplied security
	 * policy directive(s).
	 *
	 * @param policyDirectives the security policy directive(s)
	 * @throws IllegalArgumentException if policyDirectives is {@code null} or empty
	 */
	public FeaturePolicyHeaderWriter(String policyDirectives) {
		setPolicyDirectives(policyDirectives);
	}

	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (!response.containsHeader(FEATURE_POLICY_HEADER)) {
			response.setHeader(FEATURE_POLICY_HEADER, this.policyDirectives);
		}
	}

	/**
	 * Set the security policy directive(s) to be used in the response header.
	 *
	 * @param policyDirectives the security policy directive(s)
	 * @throws IllegalArgumentException if policyDirectives is {@code null} or empty
	 */
	public void setPolicyDirectives(String policyDirectives) {
		Assert.hasLength(policyDirectives, "policyDirectives must not be null or empty");
		this.policyDirectives = policyDirectives;
	}

	@Override
	public String toString() {
		return getClass().getName() + " [policyDirectives=" + this.policyDirectives + "]";
	}

}
