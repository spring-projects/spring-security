/*
 * Copyright 2004-present the original author or authors.
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

import io.micrometer.context.ThreadLocalAccessor;

import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * A {@link ThreadLocalAccessor} for accessing a {@link ServerWebExchange}.
 * <p>
 * This class adapts the existing Reactor Context attribute
 * {@code ServerWebExchange.class} to the {@link ThreadLocalAccessor} contract to allow
 * Micrometer Context Propagation to automatically propagate a {@link ServerWebExchange}
 * in Reactive applications. It is automatically registered with the
 * {@link io.micrometer.context.ContextRegistry} through the
 * {@link java.util.ServiceLoader} mechanism when context-propagation is on the classpath.
 *
 * @author Steve Riesenberg
 * @since 6.5
 * @see io.micrometer.context.ContextRegistry
 */
public final class ServerWebExchangeThreadLocalAccessor implements ThreadLocalAccessor<ServerWebExchange> {

	private static final ThreadLocal<ServerWebExchange> threadLocal = new ThreadLocal<>();

	@Override
	public Object key() {
		return ServerWebExchange.class;
	}

	@Override
	public ServerWebExchange getValue() {
		return threadLocal.get();
	}

	@Override
	public void setValue(ServerWebExchange exchange) {
		Assert.notNull(exchange, "exchange cannot be null");
		threadLocal.set(exchange);
	}

	@Override
	public void setValue() {
		threadLocal.remove();
	}

}
