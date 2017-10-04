/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.client.authentication;

import org.springframework.core.ResolvableType;
import org.springframework.util.Assert;

import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * An implementation of an {@link AuthorizationGrantAuthenticator} that
 * simply delegates to one of the {@link AuthorizationGrantAuthenticator}'s that it composes.
 *
 * @author Joe Grandja
 * @since 5.0
 */
public class DelegatingAuthorizationGrantAuthenticator<T extends AuthorizationGrantAuthenticationToken> implements AuthorizationGrantAuthenticator<T> {
	private final Map<Class<? extends AuthorizationGrantAuthenticationToken>, List<AuthorizationGrantAuthenticator<T>>> authenticators = new HashMap<>();

	public DelegatingAuthorizationGrantAuthenticator(List<AuthorizationGrantAuthenticator<T>> authenticators) {
		Assert.notEmpty(authenticators, "authenticators cannot be empty");
		authenticators.forEach(authenticator -> {
			Class<? extends AuthorizationGrantAuthenticationToken> authenticationType =
				ResolvableType.forInstance(authenticator).as(AuthorizationGrantAuthenticator.class)
					.resolveGeneric(0).asSubclass(AuthorizationGrantAuthenticationToken.class);
			this.authenticators
				.computeIfAbsent(authenticationType, k -> new LinkedList<>())
				.add(authenticator);
		});
	}

	@Override
	public OAuth2ClientAuthenticationToken authenticate(T authorizationGrantAuthentication) throws OAuth2AuthenticationException {
		return this.authenticators.getOrDefault(authorizationGrantAuthentication.getClass(), Collections.emptyList())
			.stream()
			.map(authenticator -> authenticator.authenticate(authorizationGrantAuthentication))
			.filter(Objects::nonNull)
			.findFirst()
			.orElse(null);
	}
}
