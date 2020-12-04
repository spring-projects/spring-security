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

package org.springframework.security.web.header.writers;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

/**
 * Provides support for
 * <a href="https://w3c.github.io/webappsec-permissions-policy//">Permisisons Policy</a>.
 * <p>
 * Permissions Policy allows web developers to selectively enable, disable, and modify the
 * behavior of certain APIs and web features in the browser.
 * <p>
 * A declaration of a permissions policy contains a set of security policies, each
 * responsible for declaring the restrictions for a particular feature type.
 *
 * @author Christophe Gilles
 * @since 5.5
 */
public final class PermissionsPolicyHeaderWriter implements HeaderWriter {

	private static final String PERMISSIONS_POLICY_HEADER = "Permissions-Policy";

	private String policy;

	/**
	 * Create a new instance of {@link PermissionsPolicyHeaderWriter}.
	 */
	public PermissionsPolicyHeaderWriter() {
	}

	/**
	 * Create a new instance of {@link PermissionsPolicyHeaderWriter} with supplied
	 * security policy.
	 * @param policy the security policy
	 * @throws IllegalArgumentException if policy is {@code null} or empty
	 */
	public PermissionsPolicyHeaderWriter(String policy) {
		setPolicy(policy);
	}

	/**
	 * Sets the policy to be used in the response header.
	 * @param policy a permissions policy
	 * @throws IllegalArgumentException if policy is null
	 */
	public void setPolicy(String policy) {
		Assert.hasLength(policy, "policy can not be null or empty");
		this.policy = policy;
	}

	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (!response.containsHeader(PERMISSIONS_POLICY_HEADER)) {
			response.setHeader(PERMISSIONS_POLICY_HEADER, this.policy);
		}
	}

	@Override
	public String toString() {
		return getClass().getName() + " [policy=" + this.policy + "]";
	}

}
