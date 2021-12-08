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
 * Inserts Cross-Origin-Embedder-Policy header.
 *
 * @author Marcus Da Coregio
 * @since 5.7
 * @see <a href=
 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy">
 * Cross-Origin-Embedder-Policy</a>
 */
public final class CrossOriginEmbedderPolicyHeaderWriter implements HeaderWriter {

	private static final String EMBEDDER_POLICY = "Cross-Origin-Embedder-Policy";

	private CrossOriginEmbedderPolicy policy;

	/**
	 * Sets the {@link CrossOriginEmbedderPolicy} value to be used in the
	 * {@code Cross-Origin-Embedder-Policy} header
	 * @param embedderPolicy the {@link CrossOriginEmbedderPolicy} to use
	 */
	public void setPolicy(CrossOriginEmbedderPolicy embedderPolicy) {
		Assert.notNull(embedderPolicy, "embedderPolicy cannot be null");
		this.policy = embedderPolicy;
	}

	@Override
	public void writeHeaders(HttpServletRequest request, HttpServletResponse response) {
		if (this.policy != null && !response.containsHeader(EMBEDDER_POLICY)) {
			response.addHeader(EMBEDDER_POLICY, this.policy.getPolicy());
		}
	}

	public enum CrossOriginEmbedderPolicy {

		UNSAFE_NONE("unsafe-none"),

		REQUIRE_CORP("require-corp");

		private final String policy;

		CrossOriginEmbedderPolicy(String policy) {
			this.policy = policy;
		}

		public String getPolicy() {
			return this.policy;
		}

		public static CrossOriginEmbedderPolicy from(String embedderPolicy) {
			for (CrossOriginEmbedderPolicy policy : values()) {
				if (policy.getPolicy().equals(embedderPolicy)) {
					return policy;
				}
			}
			return null;
		}

	}

}
