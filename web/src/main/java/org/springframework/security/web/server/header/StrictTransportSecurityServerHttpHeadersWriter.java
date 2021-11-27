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

import java.time.Duration;

import reactor.core.publisher.Mono;

import org.springframework.security.web.server.header.StaticServerHttpHeadersWriter.Builder;
import org.springframework.web.server.ServerWebExchange;

/**
 * Writes the Strict-Transport-Security if the request is secure.
 *
 * @author Rob Winch
 * @author Ankur Pathak
 * @since 5.0
 */
public final class StrictTransportSecurityServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	public static final String STRICT_TRANSPORT_SECURITY = "Strict-Transport-Security";

	private String maxAge;

	private String subdomain;

	private String preload;

	private ServerHttpHeadersWriter delegate;

	public StrictTransportSecurityServerHttpHeadersWriter() {
		setIncludeSubDomains(true);
		setMaxAge(Duration.ofDays(365L));
		setPreload(false);
		updateDelegate();
	}

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		return isSecure(exchange) ? this.delegate.writeHttpHeaders(exchange) : Mono.empty();
	}

	/**
	 * Sets if subdomains should be included. Default is true
	 * @param includeSubDomains if subdomains should be included
	 */
	public void setIncludeSubDomains(boolean includeSubDomains) {
		this.subdomain = includeSubDomains ? " ; includeSubDomains" : "";
		updateDelegate();
	}

	/**
	 * <p>
	 * Sets if preload should be included. Default is false
	 * </p>
	 *
	 * <p>
	 * See <a href="https://hstspreload.org/">Website hstspreload.org</a> for additional
	 * details.
	 * </p>
	 * @param preload if preload should be included
	 * @since 5.2.0
	 */
	public void setPreload(boolean preload) {
		this.preload = preload ? " ; preload" : "";
		updateDelegate();
	}

	/**
	 * Sets the max age of the header. Default is a year.
	 * @param maxAge the max age of the header
	 */
	public void setMaxAge(Duration maxAge) {
		this.maxAge = "max-age=" + maxAge.getSeconds();
		updateDelegate();
	}

	private void updateDelegate() {
		Builder builder = StaticServerHttpHeadersWriter.builder();
		builder.header(STRICT_TRANSPORT_SECURITY, this.maxAge + this.subdomain + this.preload);
		this.delegate = builder.build();
	}

	private boolean isSecure(ServerWebExchange exchange) {
		String scheme = exchange.getRequest().getURI().getScheme();
		boolean isSecure = scheme != null && scheme.equalsIgnoreCase("https");
		return isSecure;
	}

}
