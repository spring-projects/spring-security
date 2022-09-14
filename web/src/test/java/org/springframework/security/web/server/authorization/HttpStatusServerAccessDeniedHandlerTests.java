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

package org.springframework.security.web.server.authorization;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class HttpStatusServerAccessDeniedHandlerTests {

	@Mock
	private ServerWebExchange exchange;

	private HttpStatus httpStatus = HttpStatus.FORBIDDEN;

	private HttpStatusServerAccessDeniedHandler handler = new HttpStatusServerAccessDeniedHandler(this.httpStatus);

	private AccessDeniedException exception = new AccessDeniedException("Forbidden");

	@Test
	public void constructorHttpStatusWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new HttpStatusServerAccessDeniedHandler(null));
	}

	@Test
	public void commenceWhenNoSubscribersThenNoActions() {
		this.handler.handle(this.exchange, this.exception);
		verifyNoMoreInteractions(this.exchange);
	}

	@Test
	public void commenceWhenSubscribeThenStatusSet() {
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		this.handler.handle(this.exchange, this.exception).block();
		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(this.httpStatus);
	}

	@Test
	public void commenceWhenCustomStatusSubscribeThenStatusSet() {
		this.httpStatus = HttpStatus.NOT_FOUND;
		this.handler = new HttpStatusServerAccessDeniedHandler(this.httpStatus);
		this.exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/").build());
		this.handler.handle(this.exchange, this.exception).block();
		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(this.httpStatus);
	}

}
