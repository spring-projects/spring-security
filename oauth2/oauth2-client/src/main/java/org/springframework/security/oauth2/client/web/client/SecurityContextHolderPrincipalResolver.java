/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.oauth2.client.web.client;

import org.springframework.http.HttpRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;

/**
 * A strategy for resolving a {@link Authentication principal} from an intercepted request
 * using the {@link SecurityContextHolder}.
 *
 * @author Steve Riesenberg
 * @since 6.4
 */
public class SecurityContextHolderPrincipalResolver implements OAuth2ClientHttpRequestInterceptor.PrincipalResolver {

	private final SecurityContextHolderStrategy securityContextHolderStrategy;

	/**
	 * Constructs a {@code SecurityContextHolderPrincipalResolver}.
	 */
	public SecurityContextHolderPrincipalResolver() {
		this(SecurityContextHolder.getContextHolderStrategy());
	}

	/**
	 * Constructs a {@code SecurityContextHolderPrincipalResolver} using the provided
	 * parameters.
	 * @param securityContextHolderStrategy the {@link SecurityContextHolderStrategy} to
	 * use for resolving the {@link Authentication principal}
	 */
	public SecurityContextHolderPrincipalResolver(SecurityContextHolderStrategy securityContextHolderStrategy) {
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	@Override
	public Authentication resolve(HttpRequest request) {
		return this.securityContextHolderStrategy.getContext().getAuthentication();
	}

}
