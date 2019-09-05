/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;

/**
 * An {@link AuthenticationManagerResolver} that returns a {@link AuthenticationManager}
 * instances based upon the type of {@link HttpServletRequest} passed into
 * {@link #resolve(HttpServletRequest)}.
 *
 * @author Josh Cummings
 * @since 5.7
 */
public final class RequestMatcherDelegatingAuthenticationManagerResolver
		implements AuthenticationManagerResolver<HttpServletRequest> {

	private final List<RequestMatcherEntry<AuthenticationManager>> authenticationManagers;

	private AuthenticationManager defaultAuthenticationManager = (authentication) -> {
		throw new AuthenticationServiceException("Cannot authenticate " + authentication);
	};

	/**
	 * Construct an {@link RequestMatcherDelegatingAuthenticationManagerResolver} based on
	 * the provided parameters
	 * @param authenticationManagers a {@link Map} of
	 * {@link RequestMatcher}/{@link AuthenticationManager} pairs
	 */
	RequestMatcherDelegatingAuthenticationManagerResolver(
			RequestMatcherEntry<AuthenticationManager>... authenticationManagers) {
		Assert.notEmpty(authenticationManagers, "authenticationManagers cannot be empty");
		this.authenticationManagers = Arrays.asList(authenticationManagers);
	}

	/**
	 * Construct an {@link RequestMatcherDelegatingAuthenticationManagerResolver} based on
	 * the provided parameters
	 * @param authenticationManagers a {@link Map} of
	 * {@link RequestMatcher}/{@link AuthenticationManager} pairs
	 */
	RequestMatcherDelegatingAuthenticationManagerResolver(
			List<RequestMatcherEntry<AuthenticationManager>> authenticationManagers) {
		Assert.notEmpty(authenticationManagers, "authenticationManagers cannot be empty");
		this.authenticationManagers = authenticationManagers;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public AuthenticationManager resolve(HttpServletRequest context) {
		for (RequestMatcherEntry<AuthenticationManager> entry : this.authenticationManagers) {
			if (entry.getRequestMatcher().matches(context)) {
				return entry.getEntry();
			}
		}

		return this.defaultAuthenticationManager;
	}

	/**
	 * Set the default {@link AuthenticationManager} to use when a request does not match
	 * @param defaultAuthenticationManager the default {@link AuthenticationManager} to
	 * use
	 */
	public void setDefaultAuthenticationManager(AuthenticationManager defaultAuthenticationManager) {
		Assert.notNull(defaultAuthenticationManager, "defaultAuthenticationManager cannot be null");
		this.defaultAuthenticationManager = defaultAuthenticationManager;
	}

	/**
	 * Creates a builder for {@link RequestMatcherDelegatingAuthorizationManager}.
	 * @return the new {@link RequestMatcherDelegatingAuthorizationManager.Builder}
	 * instance
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link RequestMatcherDelegatingAuthenticationManagerResolver}.
	 */
	public static final class Builder {

		private final List<RequestMatcherEntry<AuthenticationManager>> entries = new ArrayList<>();

		private Builder() {

		}

		/**
		 * Maps a {@link RequestMatcher} to an {@link AuthorizationManager}.
		 * @param matcher the {@link RequestMatcher} to use
		 * @param manager the {@link AuthenticationManager} to use
		 * @return the {@link Builder} for further
		 * customizationServerWebExchangeDelegatingReactiveAuthenticationManagerResolvers
		 */
		public Builder add(RequestMatcher matcher, AuthenticationManager manager) {
			Assert.notNull(matcher, "matcher cannot be null");
			Assert.notNull(manager, "manager cannot be null");
			this.entries.add(new RequestMatcherEntry<>(matcher, manager));
			return this;
		}

		/**
		 * Creates a {@link RequestMatcherDelegatingAuthenticationManagerResolver}
		 * instance.
		 * @return the {@link RequestMatcherDelegatingAuthenticationManagerResolver}
		 * instance
		 */
		public RequestMatcherDelegatingAuthenticationManagerResolver build() {
			return new RequestMatcherDelegatingAuthenticationManagerResolver(this.entries);
		}

	}

}
