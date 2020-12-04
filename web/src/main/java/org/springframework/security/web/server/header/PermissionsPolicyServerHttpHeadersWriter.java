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

package org.springframework.security.web.server.header;

import reactor.core.publisher.Mono;

import org.springframework.security.web.server.header.StaticServerHttpHeadersWriter.Builder;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Writes the {@code Permissions-Policy} response header with configured policy
 * directives.
 *
 * @author Christophe Gilles
 * @since 5.5
 */
public final class PermissionsPolicyServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	public static final String PERMISSIONS_POLICY = "Permissions-Policy";

	private ServerHttpHeadersWriter delegate;

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return (this.delegate != null) ? this.delegate.writeHttpHeaders(exchange) : Mono.empty();
	}

	private static ServerHttpHeadersWriter createDelegate(String policyDirectives) {
		Builder builder = StaticServerHttpHeadersWriter.builder();
		builder.header(PERMISSIONS_POLICY, policyDirectives);
		return builder.build();
	}

	/**
	 * Set the policy to be used in the response header.
	 * @param policy the policy
	 * @throws IllegalArgumentException if policy is {@code null}
	 */
	public void setPolicy(String policy) {
		Assert.notNull(policy, "policy must not be null");
		this.delegate = createDelegate(policy);
	}

}
