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

package org.springframework.security.web.server.authentication;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.authentication.ReactiveAuthenticationManagerResolver;
import org.springframework.security.web.access.intercept.RequestMatcherDelegatingAuthorizationManager;
import org.springframework.security.web.authentication.RequestMatcherDelegatingAuthenticationManagerResolver;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.util.Assert;
import org.springframework.web.server.ServerWebExchange;

/**
 * A {@link ReactiveAuthenticationManagerResolver} that returns a
 * {@link ReactiveAuthenticationManager} instances based upon the type of
 * {@link ServerWebExchange} passed into {@link #resolve(ServerWebExchange)}.
 *
 * @author Josh Cummings
 * @since 5.7
 *
 */
public final class ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver
		implements ReactiveAuthenticationManagerResolver<ServerWebExchange> {

	private final List<ServerWebExchangeMatcherEntry<ReactiveAuthenticationManager>> authenticationManagers;

	private ReactiveAuthenticationManager defaultAuthenticationManager = (authentication) -> Mono
			.error(new AuthenticationServiceException("Cannot authenticate " + authentication));

	/**
	 * Construct an
	 * {@link ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver} based on
	 * the provided parameters
	 * @param managers a set of {@link ServerWebExchangeMatcherEntry}s
	 */
	ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver(
			ServerWebExchangeMatcherEntry<ReactiveAuthenticationManager>... managers) {
		this(Arrays.asList(managers));
	}

	/**
	 * Construct an
	 * {@link ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver} based on
	 * the provided parameters
	 * @param managers a {@link List} of {@link ServerWebExchangeMatcherEntry}s
	 */
	ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver(
			List<ServerWebExchangeMatcherEntry<ReactiveAuthenticationManager>> managers) {
		Assert.notNull(managers, "entries cannot be null");
		this.authenticationManagers = managers;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Mono<ReactiveAuthenticationManager> resolve(ServerWebExchange exchange) {
		return Flux.fromIterable(this.authenticationManagers).filterWhen((entry) -> isMatch(exchange, entry)).next()
				.map(ServerWebExchangeMatcherEntry::getEntry).defaultIfEmpty(this.defaultAuthenticationManager);
	}

	/**
	 * Set the default {@link ReactiveAuthenticationManager} to use when a request does
	 * not match
	 * @param defaultAuthenticationManager the default
	 * {@link ReactiveAuthenticationManager} to use
	 */
	public void setDefaultAuthenticationManager(ReactiveAuthenticationManager defaultAuthenticationManager) {
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

	private Mono<Boolean> isMatch(ServerWebExchange exchange,
			ServerWebExchangeMatcherEntry<ReactiveAuthenticationManager> entry) {
		ServerWebExchangeMatcher matcher = entry.getMatcher();
		return matcher.matches(exchange).map(ServerWebExchangeMatcher.MatchResult::isMatch);
	}

	/**
	 * A builder for {@link RequestMatcherDelegatingAuthenticationManagerResolver}.
	 */
	public static final class Builder {

		private final List<ServerWebExchangeMatcherEntry<ReactiveAuthenticationManager>> entries = new ArrayList<>();

		private Builder() {

		}

		/**
		 * Maps a {@link ServerWebExchangeMatcher} to an
		 * {@link ReactiveAuthenticationManager}.
		 * @param matcher the {@link ServerWebExchangeMatcher} to use
		 * @param manager the {@link ReactiveAuthenticationManager} to use
		 * @return the
		 * {@link RequestMatcherDelegatingAuthenticationManagerResolver.Builder} for
		 * further customizations
		 */
		public ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver.Builder add(
				ServerWebExchangeMatcher matcher, ReactiveAuthenticationManager manager) {
			Assert.notNull(matcher, "matcher cannot be null");
			Assert.notNull(manager, "manager cannot be null");
			this.entries.add(new ServerWebExchangeMatcherEntry<>(matcher, manager));
			return this;
		}

		/**
		 * Creates a {@link RequestMatcherDelegatingAuthenticationManagerResolver}
		 * instance.
		 * @return the {@link RequestMatcherDelegatingAuthenticationManagerResolver}
		 * instance
		 */
		public ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver build() {
			return new ServerWebExchangeDelegatingReactiveAuthenticationManagerResolver(this.entries);
		}

	}

}
