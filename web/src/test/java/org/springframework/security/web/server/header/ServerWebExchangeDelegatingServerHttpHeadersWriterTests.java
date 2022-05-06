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

import java.util.Collections;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author David Herberth
 */
@ExtendWith(MockitoExtension.class)
public class ServerWebExchangeDelegatingServerHttpHeadersWriterTests {

	@Mock
	private ServerWebExchangeMatcher matcher;

	@Mock
	private ServerHttpHeadersWriter delegate;

	private ServerWebExchange exchange;

	private ServerWebExchangeDelegatingServerHttpHeadersWriter headerWriter;

	@BeforeEach
	public void setup() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
		this.headerWriter = new ServerWebExchangeDelegatingServerHttpHeadersWriter(this.matcher, this.delegate);
	}

	@Test
	public void constructorWhenNullWebExchangeMatcherThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new ServerWebExchangeDelegatingServerHttpHeadersWriter(null, this.delegate))
				.withMessage("webExchangeMatcher cannot be null");
	}

	@Test
	public void constructorWhenNullWebExchangeMatcherEntryThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new ServerWebExchangeDelegatingServerHttpHeadersWriter(null))
				.withMessage("headersWriter cannot be null");
	}

	@Test
	public void constructorWhenNullDelegateHeadersWriterThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new ServerWebExchangeDelegatingServerHttpHeadersWriter(this.matcher, null))
				.withMessage("delegateHeadersWriter cannot be null");
	}

	@Test
	public void constructorWhenEntryWithNullMatcherThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new ServerWebExchangeDelegatingServerHttpHeadersWriter(
						new ServerWebExchangeMatcherEntry<>(null, this.delegate)))
				.withMessage("webExchangeMatcher cannot be null");
	}

	@Test
	public void constructorWhenEntryWithNullEntryThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new ServerWebExchangeDelegatingServerHttpHeadersWriter(
						new ServerWebExchangeMatcherEntry<>(this.matcher, null)))
				.withMessage("delegateHeadersWriter cannot be null");
	}

	@Test
	public void writeHeadersWhenMatchThenDelegateWriteHttpHeaders() {
		given(this.matcher.matches(this.exchange))
				.willReturn(ServerWebExchangeMatcher.MatchResult.match(Collections.emptyMap()));
		given(this.delegate.writeHttpHeaders(this.exchange)).willReturn(Mono.empty());
		this.headerWriter.writeHttpHeaders(this.exchange).block();
		verify(this.delegate).writeHttpHeaders(this.exchange);
	}

	@Test
	public void writeHeadersWhenNoMatchThenDelegateNotCalled() {
		given(this.matcher.matches(this.exchange)).willReturn(ServerWebExchangeMatcher.MatchResult.notMatch());
		this.headerWriter.writeHttpHeaders(this.exchange).block();
		verify(this.matcher).matches(this.exchange);
		verify(this.delegate, times(0)).writeHttpHeaders(this.exchange);
	}

}
