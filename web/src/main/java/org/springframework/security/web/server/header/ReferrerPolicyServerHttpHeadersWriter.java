/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.server.header;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import reactor.core.publisher.Mono;

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Writes the {@code Referrer-Policy} response header.
 *
 * @author Vedran Pavic
 * @since 5.1
 */
public final class ReferrerPolicyServerHttpHeadersWriter
		implements ServerHttpHeadersWriter {

	public static final String REFERRER_POLICY = "Referrer-Policy";

	private ServerHttpHeadersWriter delegate;

	public ReferrerPolicyServerHttpHeadersWriter() {
		this.delegate = createDelegate(ReferrerPolicy.NO_REFERRER);
	}

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return this.delegate.writeHttpHeaders(exchange);
	}

	/**
	 * Set the policy to be used in the response header.
	 * @param policy the policy
	 * @throws IllegalArgumentException if policy is {@code null}
	 */
	public void setPolicy(ReferrerPolicy policy) {
		Assert.notNull(policy, "policy must not be null");
		this.delegate = createDelegate(policy);
	}

	private static ServerHttpHeadersWriter createDelegate(ReferrerPolicy policy) {
		// @formatter:off
		return StaticServerHttpHeadersWriter.builder()
				.header(REFERRER_POLICY, policy.getPolicy())
				.build();
		// @formatter:on
	}

	public enum ReferrerPolicy {

		// @formatter:off
		NO_REFERRER("no-referrer"),
		NO_REFERRER_WHEN_DOWNGRADE("no-referrer-when-downgrade"),
		SAME_ORIGIN("same-origin"),
		ORIGIN("origin"),
		STRICT_ORIGIN("strict-origin"),
		ORIGIN_WHEN_CROSS_ORIGIN("origin-when-cross-origin"),
		STRICT_ORIGIN_WHEN_CROSS_ORIGIN("strict-origin-when-cross-origin"),
		UNSAFE_URL("unsafe-url");
		// @formatter:on

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

	}

}
