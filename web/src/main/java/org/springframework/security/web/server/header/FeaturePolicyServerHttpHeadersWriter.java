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

import reactor.core.publisher.Mono;

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Writes the {@code Feature-Policy} response header with configured policy directives.
 *
 * @author Vedran Pavic
 * @since 5.1
 */
public final class FeaturePolicyServerHttpHeadersWriter
		implements ServerHttpHeadersWriter {

	public static final String FEATURE_POLICY = "Feature-Policy";

	private ServerHttpHeadersWriter delegate;

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return (this.delegate != null) ? this.delegate.writeHttpHeaders(exchange)
				: Mono.empty();
	}

	/**
	 * Set the policy directive(s) to be used in the response header.
	 *
	 * @param policyDirectives the policy directive(s)
	 * @throws IllegalArgumentException if policyDirectives is {@code null} or empty
	 */
	public void setPolicyDirectives(String policyDirectives) {
		Assert.hasLength(policyDirectives, "policyDirectives must not be null or empty");
		this.delegate = createDelegate(policyDirectives);
	}

	private static ServerHttpHeadersWriter createDelegate(String policyDirectives) {
		// @formatter:off
		return StaticServerHttpHeadersWriter.builder()
				.header(FEATURE_POLICY, policyDirectives)
				.build();
		// @formatter:on
	}

}
