/*
 * Copyright 2002-2017 the original author or authors.
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

import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

/**
 * Add the x-xss-protection header.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class XXssProtectionServerHttpHeadersWriter implements ServerHttpHeadersWriter {
	public static final String X_XSS_PROTECTION = "X-XSS-Protection";

	private boolean enabled;

	private boolean block;

	private ServerHttpHeadersWriter delegate;

	/**
	 * Creates a new instance
	 */
	public XXssProtectionServerHttpHeadersWriter() {
		this.enabled = true;
		this.block = true;
		updateDelegate();
	}

	/* (non-Javadoc)
	 * @see org.springframework.security.web.server.HttpHeadersWriter#writeHttpHeaders(org.springframework.web.server.ServerWebExchange)
	 */
	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return delegate.writeHttpHeaders(exchange);
	}

	/**
	 * If true, will contain a value of 1. For example:
	 *
	 * <pre>
	 * X-XSS-Protection: 1
	 * </pre>
	 *
	 * or if {@link #setBlock(boolean)} is true
	 *
	 *
	 * <pre>
	 * X-XSS-Protection: 1; mode=block
	 * </pre>
	 *
	 * If false, will explicitly disable specify that X-XSS-Protection is disabled. For
	 * example:
	 *
	 * <pre>
	 * X-XSS-Protection: 0
	 * </pre>
	 *
	 * @param enabled the new value
	 */
	public void setEnabled(boolean enabled) {
		if (!enabled) {
			setBlock(false);
		}
		this.enabled = enabled;
		updateDelegate();
	}

	/**
	 * If false, will not specify the mode as blocked. In this instance, any content will
	 * be attempted to be fixed. If true, the content will be replaced with "#".
	 *
	 * @param block the new value
	 */
	public void setBlock(boolean block) {
		if (!enabled && block) {
			throw new IllegalArgumentException(
					"Cannot set block to true with enabled false");
		}
		this.block = block;
		updateDelegate();
	}

	private void updateDelegate() {

		this.delegate = StaticServerHttpHeadersWriter.builder()
				.header(X_XSS_PROTECTION, createHeaderValue())
				.build();
	}

	private String createHeaderValue() {
		if (!enabled) {
			return  "0";
		}
		if(!block) {
			return "1";
		}
		return "1 ; mode=block";
	}
}
