/*
 * Copyright 2002-2021 the original author or authors.
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
 * Inserts the Cross-Origin-Opener-Policy header
 *
 * @author Marcus Da Coregio
 * @since 5.7
 * @see <a href=
 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy">
 * Cross-Origin-Opener-Policy</a>
 */
public final class CrossOriginOpenerPolicyHeaderWriter implements HeaderWriter {

	private static final String OPENER_POLICY = "Cross-Origin-Opener-Policy";

	private CrossOriginOpenerPolicy policy;

	/**
	 * Sets the {@link CrossOriginOpenerPolicy} value to be used in the
	 * {@code Cross-Origin-Opener-Policy} header
	 * @param openerPolicy the {@link CrossOriginOpenerPolicy} to use
	 */
	public void setPolicy(CrossOriginOpenerPolicy openerPolicy) {
		Assert.notNull(openerPolicy, "openerPolicy cannot be null");
		this.policy = openerPolicy;
	}

	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (this.policy != null && !response.containsHeader(OPENER_POLICY)) {
			response.addHeader(OPENER_POLICY, this.policy.getPolicy());
		}
	}

	public enum CrossOriginOpenerPolicy {

		UNSAFE_NONE("unsafe-none"),

		SAME_ORIGIN_ALLOW_POPUPS("same-origin-allow-popups"),

		SAME_ORIGIN("same-origin");

		private final String policy;

		CrossOriginOpenerPolicy(String policy) {
			this.policy = policy;
		}

		public String getPolicy() {
			return this.policy;
		}

		public static CrossOriginOpenerPolicy from(String openerPolicy) {
			for (CrossOriginOpenerPolicy policy : values()) {
				if (policy.getPolicy().equals(openerPolicy)) {
					return policy;
				}
			}
			return null;
		}

	}

}
