/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.web;

import java.util.concurrent.CountDownLatch;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.task.SimpleAsyncTaskExecutor;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.web.server.ServerWebExchangeThreadLocalAccessor;
import org.springframework.web.server.ServerWebExchange;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests for {@link ServerWebExchangeThreadLocalAccessor}.
 *
 * @author Steve Riesenberg
 */
public class ServerWebExchangeThreadLocalAccessorTests {

	private ServerWebExchangeThreadLocalAccessor threadLocalAccessor;

	private ServerWebExchange exchange;

	@BeforeEach
	public void setUp() {
		this.threadLocalAccessor = new ServerWebExchangeThreadLocalAccessor();
		this.exchange = MockServerWebExchange.builder(MockServerHttpRequest.get("/")).build();
	}

	@AfterEach
	public void tearDown() {
		this.threadLocalAccessor.setValue();
	}

	@Test
	public void keyAlwaysReturnsServerWebExchangeClass() {
		assertThat(this.threadLocalAccessor.key()).isEqualTo(ServerWebExchange.class);
	}

	@Test
	public void getValueWhenThreadLocalNotSetThenReturnsNull() {
		assertThat(this.threadLocalAccessor.getValue()).isNull();
	}

	@Test
	public void getValueWhenThreadLocalSetThenReturnsServerWebExchange() {
		this.threadLocalAccessor.setValue(this.exchange);
		assertThat(this.threadLocalAccessor.getValue()).isSameAs(this.exchange);
	}

	@Test
	public void getValueWhenThreadLocalSetOnAnotherThreadThenReturnsNull() throws InterruptedException {
		CountDownLatch threadLocalSet = new CountDownLatch(1);
		CountDownLatch threadLocalRead = new CountDownLatch(1);
		CountDownLatch threadLocalCleared = new CountDownLatch(1);

		Runnable task = () -> {
			this.threadLocalAccessor.setValue(this.exchange);
			threadLocalSet.countDown();
			try {
				threadLocalRead.await();
			}
			catch (InterruptedException ignored) {
			}
			finally {
				this.threadLocalAccessor.setValue();
				threadLocalCleared.countDown();
			}
		};
		try (SimpleAsyncTaskExecutor taskExecutor = new SimpleAsyncTaskExecutor()) {
			taskExecutor.execute(task);
			threadLocalSet.await();
			assertThat(this.threadLocalAccessor.getValue()).isNull();
			threadLocalRead.countDown();
			threadLocalCleared.await();
		}
	}

	@Test
	public void setValueWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.threadLocalAccessor.setValue(null))
			.withMessage("exchange cannot be null");
		// @formatter:on
	}

	@Test
	public void setValueWhenThreadLocalSetThenClearsThreadLocal() {
		this.threadLocalAccessor.setValue(this.exchange);
		assertThat(this.threadLocalAccessor.getValue()).isSameAs(this.exchange);

		this.threadLocalAccessor.setValue();
		assertThat(this.threadLocalAccessor.getValue()).isNull();
	}

}
