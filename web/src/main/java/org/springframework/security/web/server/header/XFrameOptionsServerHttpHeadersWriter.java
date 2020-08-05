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

import reactor.core.publisher.Mono;

import org.springframework.web.server.ServerWebExchange;

/**
 * {@code ServerHttpHeadersWriter} implementation for the X-Frame-Options headers.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class XFrameOptionsServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	public static final String X_FRAME_OPTIONS = "X-Frame-Options";

	private ServerHttpHeadersWriter delegate = createDelegate(Mode.DENY);

	/*
	 * (non-Javadoc)
	 *
	 * @see org.springframework.security.web.server.HttpHeadersWriter#
	 * writeHttpHeaders(org.springframework.web.server.ServerWebExchange)
	 */
	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return delegate.writeHttpHeaders(exchange);
	}

	/**
	 * Sets the X-Frame-Options mode. There is no support for ALLOW-FROM because not
	 * <a href=
	 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options">all
	 * browsers support it</a>. Consider using X-Frame-Options with
	 * Content-Security-Policy <a href=
	 * "https://w3c.github.io/webappsec/specs/content-security-policy/#directive-frame-ancestors">frame-ancestors</a>.
	 * @param mode
	 */
	public void setMode(Mode mode) {
		this.delegate = createDelegate(mode);
	}

	/**
	 * The X-Frame-Options values. There is no support for ALLOW-FROM because not <a href=
	 * "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options">all
	 * browsers support it</a>. Consider using X-Frame-Options with
	 * Content-Security-Policy <a href=
	 * "https://w3c.github.io/webappsec/specs/content-security-policy/#directive-frame-ancestors">frame-ancestors</a>.
	 *
	 * @author Rob Winch
	 * @since 5.0
	 */
	public enum Mode {

		/**
		 * A browser receiving content with this header field MUST NOT display this
		 * content in any frame.
		 */
		DENY,
		/**
		 * A browser receiving content with this header field MUST NOT display this
		 * content in any frame from a page of different origin than the content itself.
		 *
		 * If a browser or plugin cannot reliably determine whether or not the origin of
		 * the content and the frame are the same, this MUST be treated as "DENY".
		 */
		SAMEORIGIN

	}

	private static ServerHttpHeadersWriter createDelegate(Mode mode) {
		// @formatter:off
		return StaticServerHttpHeadersWriter.builder().header(X_FRAME_OPTIONS, mode.name()).build();
		// @formatter:on

	}

}
