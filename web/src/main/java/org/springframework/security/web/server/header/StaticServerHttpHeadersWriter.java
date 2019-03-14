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

import java.util.Arrays;
import java.util.Collections;

import org.springframework.http.HttpHeaders;
import org.springframework.web.server.ServerWebExchange;

import reactor.core.publisher.Mono;

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

	/* (non-Javadoc)
	 * @see org.springframework.security.web.server.HttpHeadersWriter#writeHttpHeaders(org.springframework.web.server.ServerWebExchange)
	 */
	@Override
	public Mono<Void> writeHttpHeaders(ServerWebExchange exchange) {
		HttpHeaders headers = exchange.getResponse().getHeaders();
		boolean containsOneHeaderToAdd = Collections.disjoint(headers.keySet(), this.headersToAdd.keySet());
		if (containsOneHeaderToAdd) {
			this.headersToAdd.forEach((name, values) -> {
				headers.put(name, values);
			});
		}
		return Mono.empty();
	}

	public static Builder builder() {
		return new Builder();
	}

	public static class Builder {
		private HttpHeaders headers = new HttpHeaders();

		public Builder header(String headerName, String...values) {
			headers.put(headerName, Arrays.asList(values));
			return this;
		}

		public StaticServerHttpHeadersWriter build() {
			return new StaticServerHttpHeadersWriter(headers);
		}
	}
}
