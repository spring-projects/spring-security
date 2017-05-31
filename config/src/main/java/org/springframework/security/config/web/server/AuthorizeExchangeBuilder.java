/*
 * Copyright 2002-2017 the original author or authors.
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
package org.springframework.security.config.web.server;

import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.web.server.authorization.AuthorizationWebFilter;
import org.springframework.security.web.server.authorization.DelegatingReactiveAuthorizationManager;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcherEntry;
import org.springframework.web.server.WebFilter;
import reactor.core.publisher.Mono;

/**
 * @author Rob Winch
 * @since 5.0
 */
public class AuthorizeExchangeBuilder extends AbstractServerWebExchangeMatcherRegistry<AuthorizeExchangeBuilder.Access> {
	private DelegatingReactiveAuthorizationManager.Builder managerBldr = DelegatingReactiveAuthorizationManager.builder();
	private ServerWebExchangeMatcher matcher;
	private boolean anyExchangeRegistered;

	@Override
	public Access anyExchange() {
		Access result = super.anyExchange();
		anyExchangeRegistered = true;
		return result;
	}

	@Override
	protected Access registerMatcher(ServerWebExchangeMatcher matcher) {
		if(anyExchangeRegistered) {
			throw new IllegalStateException("Cannot register " + matcher + " which would be unreachable because anyExchange() has already been registered.");
		}
		if(this.matcher != null) {
			throw new IllegalStateException("The matcher " + matcher + " does not have an access rule defined");
		}
		this.matcher = matcher;
		return new Access();
	}

	public WebFilter build() {
		if(this.matcher != null) {
			throw new IllegalStateException("The matcher " + matcher + " does not have an access rule defined");
		}
		return new AuthorizationWebFilter(managerBldr.build());
	}

	public final class Access {

		public AuthorizeExchangeBuilder permitAll() {
			return access( (a,e) -> Mono.just(new AuthorizationDecision(true)));
		}

		public AuthorizeExchangeBuilder denyAll() {
			return access( (a,e) -> Mono.just(new AuthorizationDecision(false)));
		}

		public AuthorizeExchangeBuilder hasRole(String role) {
			return access(AuthorityAuthorizationManager.hasRole(role));
		}

		public AuthorizeExchangeBuilder hasAuthority(String authority) {
			return access(AuthorityAuthorizationManager.hasAuthority(authority));
		}

		public AuthorizeExchangeBuilder authenticated() {
			return access(AuthenticatedAuthorizationManager.authenticated());
		}

		public AuthorizeExchangeBuilder access(ReactiveAuthorizationManager<AuthorizationContext> manager) {
			managerBldr.add(new ServerWebExchangeMatcherEntry<>(matcher, manager));
			matcher = null;
			return AuthorizeExchangeBuilder.this;
		}
	}
}
