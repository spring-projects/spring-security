/*
 * Copyright 2019 the original author or authors.
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

package org.springframework.security.rsocket.core;

import io.rsocket.SocketAcceptor;
import io.rsocket.plugins.SocketAcceptorInterceptor;
import org.springframework.util.Assert;

/**
 * A SocketAcceptorInterceptor that applies Security through a delegate {@link SocketAcceptorInterceptor}. This allows
 * security to be applied lazily to an application.
 *
 * @author Rob Winch
 * @since 5.2
 */
public class SecuritySocketAcceptorInterceptor implements SocketAcceptorInterceptor {
	private final SocketAcceptorInterceptor acceptorInterceptor;

	public SecuritySocketAcceptorInterceptor(SocketAcceptorInterceptor acceptorInterceptor) {
		Assert.notNull(acceptorInterceptor, "acceptorInterceptor cannot be null");
		this.acceptorInterceptor = acceptorInterceptor;
	}

	@Override
	public SocketAcceptor apply(SocketAcceptor socketAcceptor) {
		return this.acceptorInterceptor.apply(socketAcceptor);
	}
}
