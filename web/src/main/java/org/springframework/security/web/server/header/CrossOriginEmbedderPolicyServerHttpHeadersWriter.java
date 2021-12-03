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
 * Inserts Cross-Origin-Embedder-Policy headers.
 *
 * @author Marcus Da Coregio
 * @since 5.7
 * @see <a href=
 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cross-Origin-Embedder-Policy">
 * Cross-Origin-Embedder-Policy</a>
 */
public final class CrossOriginEmbedderPolicyServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	public static final String EMBEDDER_POLICY = "Cross-Origin-Embedder-Policy";

	private ServerHttpHeadersWriter delegate;

	/**
	 * Sets the {@link CrossOriginEmbedderPolicy} value to be used in the
	 * {@code Cross-Origin-Embedder-Policy} header
	 * @param embedderPolicy the {@link CrossOriginEmbedderPolicy} to use
	 */
	public void setPolicy(CrossOriginEmbedderPolicy embedderPolicy) {
		Assert.notNull(embedderPolicy, "embedderPolicy cannot be null");
		this.delegate = createDelegate(embedderPolicy);
	}

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return (this.delegate != null) ? this.delegate.writeHttpHeaders(exchange) : Mono.empty();
	}

	private static ServerHttpHeadersWriter createDelegate(CrossOriginEmbedderPolicy embedderPolicy) {
		StaticServerHttpHeadersWriter.Builder builder = StaticServerHttpHeadersWriter.builder();
		builder.header(EMBEDDER_POLICY, embedderPolicy.getPolicy());
		return builder.build();
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

	}

}
