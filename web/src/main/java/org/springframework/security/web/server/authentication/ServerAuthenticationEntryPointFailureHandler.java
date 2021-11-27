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

package org.springframework.security.web.server.authentication;

import reactor.core.publisher.Mono;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.util.Assert;

/**
 * Adapts a {@link ServerAuthenticationEntryPoint} into a
 * {@link ServerAuthenticationFailureHandler}
 *
 * @author Rob Winch
 * @since 5.0
 */
public class ServerAuthenticationEntryPointFailureHandler implements ServerAuthenticationFailureHandler {

	private final ServerAuthenticationEntryPoint authenticationEntryPoint;

	public ServerAuthenticationEntryPointFailureHandler(ServerAuthenticationEntryPoint authenticationEntryPoint) {
		Assert.notNull(authenticationEntryPoint, "authenticationEntryPoint cannot be null");
		this.authenticationEntryPoint = authenticationEntryPoint;
	}

	@Override
	public Mono<Void> onAuthenticationFailure(WebFilterExchange webFilterExchange, AuthenticationException exception) {
		return this.authenticationEntryPoint.commence(webFilterExchange.getExchange(), exception);
	}

}
