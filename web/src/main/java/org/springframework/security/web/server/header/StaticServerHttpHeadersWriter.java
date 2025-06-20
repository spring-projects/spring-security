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

import java.util.Arrays;

import reactor.core.publisher.Mono;

import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;

/**
 * Allows specifying {@link HttpHeaders} that should be written to the response.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class StaticServerHttpHeadersWriter implements ServerHttpHeadersWriter {

	private final HttpHeaders headersToAdd;

	public StaticServerHttpHeadersWriter(HttpHeaders headersToAdd) {
		this.headersToAdd = headersToAdd;
	}

	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		HttpHeaders headers = exchange.getResponse().getHeaders();
		// Note: We need to ensure that the following algorithm compares headers
		// case insensitively, which should be true of headers.containsKey().
		boolean containsNoHeadersToAdd = true;
		for (String headerName : this.headersToAdd.headerNames()) {
			if (headers.containsHeader(headerName)) {
				containsNoHeadersToAdd = false;
				break;
			}
		}
		if (containsNoHeadersToAdd) {
			this.headersToAdd.forEach(headers::put);
		}
		return Mono.empty();
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {

		private HttpHeaders headers = new HttpHeaders();

		public Builder header(String headerName, String... values) {
			this.headers.put(headerName, Arrays.asList(values));
			return this;
		}

		public StaticServerHttpHeadersWriter build() {
			return new StaticServerHttpHeadersWriter(this.headers);
		}

	}

}
