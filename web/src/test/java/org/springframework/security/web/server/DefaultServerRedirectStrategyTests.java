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

package org.springframework.security.web.server;

import java.net.URI;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.http.HttpStatus;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class DefaultServerRedirectStrategyTests {

	@Mock
	private ServerWebExchange exchange;

	private URI location = URI.create("/login");

	private DefaultServerRedirectStrategy strategy = new DefaultServerRedirectStrategy();

	@Test
	public void sendRedirectWhenLocationNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.strategy.sendRedirect(this.exchange, null));
	}

	@Test
	public void sendRedirectWhenExchangeNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.strategy.sendRedirect(null, this.location));
	}

	@Test
	public void sendRedirectWhenNoSubscribersThenNoActions() {
		this.strategy.sendRedirect(this.exchange, this.location);
		verifyNoMoreInteractions(this.exchange);
	}

	@Test
	public void sendRedirectWhenNoContextPathThenStatusAndLocationSet() {
		this.exchange = exchange(MockServerHttpRequest.get("/"));
		this.strategy.sendRedirect(this.exchange, this.location).block();
		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
		assertThat(this.exchange.getResponse().getHeaders().getLocation()).hasPath(this.location.getPath());
	}

	@Test
	public void sendRedirectWhenContextPathSetThenStatusAndLocationSet() {
		this.exchange = exchange(MockServerHttpRequest.get("/context/foo").contextPath("/context"));
		this.strategy.sendRedirect(this.exchange, this.location).block();
		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
		assertThat(this.exchange.getResponse().getHeaders().getLocation())
				.hasPath("/context" + this.location.getPath());
	}

	@Test
	public void sendRedirectWhenContextPathSetAndAbsoluteURLThenStatusAndLocationSet() {
		this.location = URI.create("https://example.com/foo/bar");
		this.exchange = exchange(MockServerHttpRequest.get("/context/foo").contextPath("/context"));
		this.strategy.sendRedirect(this.exchange, this.location).block();
		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
		assertThat(this.exchange.getResponse().getHeaders().getLocation()).hasPath(this.location.getPath());
	}

	@Test
	public void sendRedirectWhenContextPathSetAndDisabledThenStatusAndLocationSet() {
		this.strategy.setContextRelative(false);
		this.exchange = exchange(MockServerHttpRequest.get("/context/foo").contextPath("/context"));
		this.strategy.sendRedirect(this.exchange, this.location).block();
		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.FOUND);
		assertThat(this.exchange.getResponse().getHeaders().getLocation()).hasPath(this.location.getPath());
	}

	@Test
	public void sendRedirectWhenCustomStatusThenStatusSet() {
		HttpStatus status = HttpStatus.MOVED_PERMANENTLY;
		this.strategy.setHttpStatus(status);
		this.exchange = exchange(MockServerHttpRequest.get("/"));
		this.strategy.sendRedirect(this.exchange, this.location).block();
		assertThat(this.exchange.getResponse().getStatusCode()).isEqualTo(status);
		assertThat(this.exchange.getResponse().getHeaders().getLocation()).hasPath(this.location.getPath());
	}

	@Test
	public void setHttpStatusWhenNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.strategy.setHttpStatus(null));
	}

	private static MockServerWebExchange exchange(MockServerHttpRequest.BaseBuilder<?> request) {
		return MockServerWebExchange.from(request.build());
	}

}
