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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import reactor.core.publisher.Mono;

import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.security.test.web.reactive.server.WebTestClientBuilder;
import org.springframework.security.test.web.reactive.server.WebTestHandler;
import org.springframework.security.test.web.reactive.server.WebTestHandler.WebHandlerResult;
import org.springframework.test.web.reactive.server.WebTestClient;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 * @since 5.0
 */
@RunWith(MockitoJUnitRunner.class)
public class HttpHeaderWriterWebFilterTests {

	@Mock
	ServerHttpHeadersWriter writer;

	HttpHeaderWriterWebFilter filter;

	@Before
	public void setup() {
		given(this.writer.writeHttpHeaders(any())).willReturn(Mono.empty());
		this.filter = new HttpHeaderWriterWebFilter(this.writer);
	}

	@Test
	public void filterWhenCompleteThenWritten() {
		WebTestClient rest = WebTestClientBuilder.bindToWebFilters(this.filter).build();
		rest.get().uri("/foo").exchange();
		verify(this.writer).writeHttpHeaders(any());
	}

	@Test
	public void filterWhenNotCompleteThenNotWritten() {
		WebTestHandler handler = WebTestHandler.bindToWebFilters(this.filter);
		WebHandlerResult result = handler.exchange(MockServerHttpRequest.get("/foo"));
		verify(this.writer, never()).writeHttpHeaders(any());
		result.getExchange().getResponse().setComplete().block();
		verify(this.writer).writeHttpHeaders(any());
	}

}
