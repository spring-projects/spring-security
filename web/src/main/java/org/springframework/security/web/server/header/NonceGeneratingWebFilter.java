/*
 * Copyright 2004-present the original author or authors.
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

import java.util.Base64;

import reactor.core.publisher.Mono;

import org.springframework.security.crypto.keygen.Base64StringKeyGenerator;
import org.springframework.security.crypto.keygen.StringKeyGenerator;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;

/**
 * A filter which generates a nonce string and sets it as an exchange attribute.
 *
 * <p>
 * {@link org.springframework.security.web.server.header.ContentSecurityPolicyServerHttpHeadersWriter}
 * can use the attribute to write a nonce-based Content Security Policy header, and a view
 * technology can render the nonce in generated HTML to allow intended inline
 * {@code <script>} or {@code <style>} blocks.
 *
 * <p>
 * This filter may be used to generate a nonce attribute for other purposes.
 *
 * @author Ziqin Wang
 * @since 7.1
 */
public final class NonceGeneratingWebFilter implements WebFilter {

	private final String attributeName;

	private final StringKeyGenerator nonceGenerator;

	/**
	 * Creates a new instance.
	 * @param attributeName the name of the request attribute to generate
	 * @param nonceGenerator a {@link StringKeyGenerator} for generating nonce
	 * @throws IllegalArgumentException if {@code attributeName} is null or empty string,
	 * or {@code nonceGenerator} is null
	 */
	public NonceGeneratingWebFilter(String attributeName, StringKeyGenerator nonceGenerator) {
		Assert.hasLength(attributeName, "AttributeName must not be null or empty");
		Assert.notNull(nonceGenerator, "NonceGenerator must not be null");
		this.attributeName = attributeName;
		this.nonceGenerator = nonceGenerator;
	}

	/**
	 * Creates a new instance.
	 * <p>
	 * For each exchange, the created filter will generate a secure random nonce value
	 * with 128-bit entropy and encode it as a Base64 string without padding.
	 * @param attributeName the name of the exchange attribute to generate
	 * @throws IllegalArgumentException if {@code attributeName} is null or empty string
	 */
	public NonceGeneratingWebFilter(String attributeName) {
		this(attributeName, new Base64StringKeyGenerator(Base64.getEncoder().withoutPadding(), 16));
	}

	@Override
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return Mono.fromSupplier(this.nonceGenerator::generateKey).flatMap((nonce) -> {
			exchange.getAttributes().put(this.attributeName, nonce);
			return chain.filter(exchange);
		});
	}

}
