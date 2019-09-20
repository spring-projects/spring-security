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

package org.springframework.security.config.annotation.rsocket;

import org.springframework.core.Ordered;
import org.springframework.security.config.Customizer;
import org.springframework.security.rsocket.api.PayloadInterceptor;

/**
 * The standard order for {@link PayloadInterceptor} to be
 * sorted. The actual values might change, so users should use the {@link #getOrder()} method to
 * calculate the position dynamically rather than copy values.
 *
 * @author Rob Winch
 * @since 5.2
 */
public enum PayloadInterceptorOrder implements Ordered {
	/**
	 * Where basic authentication is placed.
	 * @see RSocketSecurity#basicAuthentication(Customizer)
	 */
	BASIC_AUTHENTICATION,
	/**
	 * Where JWT based authentication is performed.
	 * @see RSocketSecurity#jwt(Customizer)
	 */
	JWT_AUTHENTICATION,
	/**
	 * A generic placeholder for other types of authentication.
	 * @see org.springframework.security.rsocket.authentication.AuthenticationPayloadInterceptor
	 */
	AUTHENTICATION,
	/**
	 * Where anonymous authentication is placed.
	 */
	ANONYMOUS,
	/**
	 * Where authorization is placed.
	 * @see org.springframework.security.rsocket.authorization.AuthorizationPayloadInterceptor
	 */
	AUTHORIZATION;

	private static final int INTERVAL = 100;

	private int order;

	PayloadInterceptorOrder() {
		this.order = ordinal() * INTERVAL;
	}

	public int getOrder() {
		return this.order;
	}
}
