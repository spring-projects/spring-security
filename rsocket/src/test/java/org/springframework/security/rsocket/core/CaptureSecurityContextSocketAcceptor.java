/*
 * Copyright 2020 the original author or authors.
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

import io.rsocket.ConnectionSetupPayload;
import io.rsocket.RSocket;
import io.rsocket.SocketAcceptor;
import reactor.core.publisher.Mono;

import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;

/**
 * A {@link SocketAcceptor} that captures the {@link SecurityContext} and then continues
 * with the {@link RSocket}
 *
 * @author Rob Winch
 */
class CaptureSecurityContextSocketAcceptor implements SocketAcceptor {

	private final RSocket accept;

	private SecurityContext securityContext;

	CaptureSecurityContextSocketAcceptor(RSocket accept) {
		this.accept = accept;
	}

	@Override
	public Mono<RSocket> accept(ConnectionSetupPayload setup, RSocket sendingSocket) {
		return ReactiveSecurityContextHolder.getContext()
				.doOnNext((securityContext) -> this.securityContext = securityContext).thenReturn(this.accept);
	}

	public SecurityContext getSecurityContext() {
		return this.securityContext;
	}

}
