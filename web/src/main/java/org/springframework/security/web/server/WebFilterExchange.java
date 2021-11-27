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

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilterChain;

/**
 * A composite of the {@link ServerWebExchange} and the {@link WebFilterChain}. This is
 * typically used as a value object for handling success and failures.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class WebFilterExchange {

	private final ServerWebExchange exchange;

	private final WebFilterChain chain;

	public WebFilterExchange(ServerWebExchange exchange, WebFilterChain chain) {
		Assert.notNull(exchange, "exchange cannot be null");
		Assert.notNull(chain, "chain cannot be null");
		this.exchange = exchange;
		this.chain = chain;
	}

	/**
	 * Get the exchange
	 * @return the exchange. Cannot be {@code null}
	 */
	public ServerWebExchange getExchange() {
		return this.exchange;
	}

	/**
	 * The filter chain
	 * @return the filter chain. Cannot be {@code null}
	 */
	public WebFilterChain getChain() {
		return this.chain;
	}

}
