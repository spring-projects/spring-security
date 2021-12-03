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

package org.springframework.security.web.server.header;

import reactor.core.publisher.Mono;

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * Inserts Cross-Origin-Opener-Policy header.
 *
 * @author Marcus Da Coregio
 * @since 5.7
 * @see <a href=
 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Opener-Policy">
 * Cross-Origin-Opener-Policy</a>
 */
public final class CrossOriginOpenerPolicyServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	public static final String OPENER_POLICY = "Cross-Origin-Opener-Policy";

	private ServerHttpHeadersWriter delegate;

	/**
	 * Sets the {@link CrossOriginOpenerPolicy} value to be used in the
	 * {@code Cross-Origin-Opener-Policy} header
	 * @param openerPolicy the {@link CrossOriginOpenerPolicy} to use
	 */
	public void setPolicy(CrossOriginOpenerPolicy openerPolicy) {
		Assert.notNull(openerPolicy, "openerPolicy cannot be null");
		this.delegate = createDelegate(openerPolicy);
	}

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return (this.delegate != null) ? this.delegate.writeHttpHeaders(exchange) : Mono.empty();
	}

	private static ServerHttpHeadersWriter createDelegate(CrossOriginOpenerPolicy openerPolicy) {
		StaticServerHttpHeadersWriter.Builder builder = StaticServerHttpHeadersWriter.builder();
		builder.header(OPENER_POLICY, openerPolicy.getPolicy());
		return builder.build();
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

	}

}
