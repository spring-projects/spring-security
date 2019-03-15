/*
 * Copyright 2002-2016 the original author or authors.
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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.web.header.HeaderWriter;
import org.springframework.util.Assert;

/**
 * <p>
 * Provides support for <a href="https://www.w3.org/TR/referrer-policy/">Referrer Policy</a>.
 * </p>
 *
 * <p>
 * The list of policies defined can be found at
 * <a href="https://www.w3.org/TR/referrer-policy/#referrer-policies">Referrer Policies</a>.
 * </p>
 *
 * <p>
 * This implementation of {@link HeaderWriter} writes the following header:
 * </p>
 * <ul>
 *  <li>Referrer-Policy</li>
 * </ul>
 *
 * <p>
 * By default, the Referrer-Policy header is not included in the response.
 * Policy <b>no-referrer</b> is used by default if no {@link ReferrerPolicy} is set.
 * </p>
 *
 * @author Eddú Meléndez
 * @author Kazuki Shimizu
 * @since 4.2
 */
public class ReferrerPolicyHeaderWriter implements HeaderWriter {

	private static final String REFERRER_POLICY_HEADER = "Referrer-Policy";

	private ReferrerPolicy policy;

	/**
	 * Creates a new instance. Default value: no-referrer.
	 */
	public ReferrerPolicyHeaderWriter() {
		this(ReferrerPolicy.NO_REFERRER);
	}

	/**
	 * Creates a new instance.
	 *
	 * @param policy a referrer policy
	 * @throws IllegalArgumentException if policy is null
	 */
	public ReferrerPolicyHeaderWriter(ReferrerPolicy policy) {
		setPolicy(policy);
	}

	/**
	 * Sets the policy to be used in the response header.
	 * @param policy a referrer policy
	 * @throws IllegalArgumentException if policy is null
	 */
	public void setPolicy(ReferrerPolicy policy) {
		Assert.notNull(policy, "policy can not be null");
		this.policy = policy;
	}

	/**
	 * @see org.springframework.security.web.header.HeaderWriter#writeHeaders(HttpServletRequest, HttpServletResponse)
	 */
	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		response.setHeader(REFERRER_POLICY_HEADER, this.policy.getPolicy());
	}

	public enum ReferrerPolicy {

		NO_REFERRER("no-referrer"),
		NO_REFERRER_WHEN_DOWNGRADE("no-referrer-when-downgrade"),
		SAME_ORIGIN("same-origin"),
		ORIGIN("origin"),
		STRICT_ORIGIN("strict-origin"),
		ORIGIN_WHEN_CROSS_ORIGIN("origin-when-cross-origin"),
		STRICT_ORIGIN_WHEN_CROSS_ORIGIN("strict-origin-when-cross-origin"),
		UNSAFE_URL("unsafe-url");

		private static final Map<String, ReferrerPolicy> REFERRER_POLICIES;

		static {
			Map<String, ReferrerPolicy> referrerPolicies = new HashMap<>();
			for (ReferrerPolicy referrerPolicy : values()) {
				referrerPolicies.put(referrerPolicy.getPolicy(), referrerPolicy);
			}
			REFERRER_POLICIES = Collections.unmodifiableMap(referrerPolicies);
		}

		private String policy;

		ReferrerPolicy(String policy) {
			this.policy = policy;
		}

		public String getPolicy() {
			return this.policy;
		}

		public static ReferrerPolicy get(String referrerPolicy) {
			return REFERRER_POLICIES.get(referrerPolicy);
		}
	}

}
