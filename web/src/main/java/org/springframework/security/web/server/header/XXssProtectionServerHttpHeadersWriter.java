/*
 * Copyright 2002-2022 the original author or authors.
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
 * Add the x-xss-protection header.
 *
 * @author Rob Winch
 * @author Daniel Garnier-Moiroux
 * @since 5.0
 */
public class XXssProtectionServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	public static final String X_XSS_PROTECTION = "X-XSS-Protection";

	private ServerHttpHeadersWriter delegate;

	private HeaderValue headerValue;

	/**
	 * Creates a new instance
	 */
	public XXssProtectionServerHttpHeadersWriter() {
		this.headerValue = HeaderValue.DISABLED;
		updateDelegate();
	}

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return this.delegate.writeHttpHeaders(exchange);
	}

	/**
	 * Sets the value of the X-XSS-PROTECTION header. Defaults to
	 * {@link HeaderValue#DISABLED}
	 * <p>
	 * If {@link HeaderValue#DISABLED}, will specify that X-XSS-Protection is disabled.
	 * For example:
	 *
	 * <pre>
	 * X-XSS-Protection: 0
	 * </pre>
	 * <p>
	 * If {@link HeaderValue#ENABLED}, will contain a value of 1, but will not specify the
	 * mode as blocked. In this instance, any content will be attempted to be fixed. For
	 * example:
	 *
	 * <pre>
	 * X-XSS-Protection: 1
	 * </pre>
	 * <p>
	 * If {@link HeaderValue#ENABLED_MODE_BLOCK}, will contain a value of 1 and will
	 * specify mode as blocked. The content will be replaced with "#". For example:
	 *
	 * <pre>
	 * X-XSS-Protection: 1 ; mode=block
	 * </pre>
	 * @param headerValue the new headerValue
	 * @throws IllegalArgumentException if headerValue is null
	 * @since 5.8
	 */
	public void setHeaderValue(HeaderValue headerValue) {
		Assert.notNull(headerValue, "headerValue cannot be null");
		this.headerValue = headerValue;
		updateDelegate();
	}

	/**
	 * The value of the x-xss-protection header. One of: "0", "1", "1 ; mode=block"
	 *
	 * @author Daniel Garnier-Moiroux
	 * @since 5.8
	 */
	public enum HeaderValue {

		DISABLED("0"), ENABLED("1"), ENABLED_MODE_BLOCK("1 ; mode=block");

		private final String value;

		HeaderValue(String value) {
			this.value = value;
		}

		@Override
		public String toString() {
			return this.value;
		}

	}

	private void updateDelegate() {
		Builder builder = StaticServerHttpHeadersWriter.builder();
		builder.header(X_XSS_PROTECTION, this.headerValue.toString());
		this.delegate = builder.build();
	}

}
