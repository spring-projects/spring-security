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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * @author Rob Winch
 * @since 5.0
 */
@ExtendWith(MockitoExtension.class)
public class WebFilterExchangeTests {

	@Mock
	private ServerWebExchange exchange;

	@Mock
	private WebFilterChain chain;

	@Test
	public void constructorServerWebExchangeWebFilterChainWhenExchangeNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new WebFilterExchange(null, this.chain));
	}

	@Test
	public void constructorServerWebExchangeWebFilterChainWhenChainNullThenException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new WebFilterExchange(this.exchange, null));
	}

	@Test
	public void getExchange() {
		WebFilterExchange filterExchange = new WebFilterExchange(this.exchange, this.chain);
		assertThat(filterExchange.getExchange()).isEqualTo(this.exchange);
	}

	@Test
	public void getChain() {
		WebFilterExchange filterExchange = new WebFilterExchange(this.exchange, this.chain);
		assertThat(filterExchange.getChain()).isEqualTo(this.chain);
	}

}
