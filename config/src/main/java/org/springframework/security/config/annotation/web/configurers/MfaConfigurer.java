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

package org.springframework.security.config.annotation.web.configurers;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.function.Supplier;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.jspecify.annotations.NullMarked;
import org.jspecify.annotations.Nullable;

import org.springframework.context.ApplicationContext;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authorization.AuthorizationRequest;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.ObjectPostProcessor;
import org.springframework.security.config.annotation.SecurityConfigurer;
import org.springframework.security.config.annotation.SecurityConfigurerAdapter;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.AuthenticationResult;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.ExpirableGrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.AuthorizationEntryPoint;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.util.Assert;

public final class MfaConfigurer<B extends HttpSecurityBuilder<B>>
		implements SecurityConfigurer<DefaultSecurityFilterChain, B> {

	private final Customizer<AuthorizeHttpRequestsConfigurer<B>> authorize;

	private final Customizer<ExceptionHandlingConfigurer<B>> exceptions;

	private Supplier<AuthenticationEntryPoint> entryPoint = Http403ForbiddenEntryPoint::new;

	private AuthoritiesGranter authoritiesGranter;

	public MfaConfigurer(String authority, SecurityConfigurerAdapter<?, B> configurer) {
		this.authoritiesGranter = new SimpleAuthoritiesGranter(authority);
		this.authorize = (a) -> a.getRegistry().hasAuthority(authority);
		this.exceptions = (e) -> e.authorizationEntryPoint(
				(p) -> p.add(new SimpleAuthorizationEntryPoint(this.entryPoint.get(), this.authoritiesGranter)));
		configurer.addObjectPostProcessor(new ObjectPostProcessor<AuthenticationManager>() {
			@Override
			public AuthenticationManager postProcess(AuthenticationManager object) {
				return new AuthoritiesGranterAuthenticationManager(object, MfaConfigurer.this.authoritiesGranter);
			}
		});
	}

	public MfaConfigurer<B> authenticationEntryPoint(Supplier<AuthenticationEntryPoint> entryPoint) {
		this.entryPoint = entryPoint;
		return this;
	}

	public MfaConfigurer<B> authenticationEntryPoint(AuthenticationEntryPoint entryPoint) {
		this.entryPoint = () -> entryPoint;
		return this;
	}

	private MfaConfigurer<B> grants(AuthoritiesGranter granter) {
		this.authoritiesGranter = new CompositeAuthoritiesGranter(this.authoritiesGranter, granter);
		return this;
	}

	public MfaConfigurer<B> grants(String... authority) {
		return grants(new SimpleAuthoritiesGranter(authority));
	}

	public MfaConfigurer<B> grants(Duration duration, String... authority) {
		return grants(new SimpleAuthoritiesGranter(duration, authority));
	}

	@Override
	public void init(B http) {
		ApplicationContext context = http.getSharedObject(ApplicationContext.class);
		SecurityContextHolderStrategy strategy = context.getBeanProvider(SecurityContextHolderStrategy.class)
			.getIfUnique(SecurityContextHolder::getContextHolderStrategy);
		grants(new PreAuthenticatedAuthoritiesGranter(strategy));
		this.authorize.customize(http.getConfigurer(AuthorizeHttpRequestsConfigurer.class));
		this.exceptions.customize(http.getConfigurer(ExceptionHandlingConfigurer.class));
	}

	@Override
	public void configure(B builder) throws Exception {

	}

	interface AuthoritiesGranter {

		Collection<GrantedAuthority> grantableAuthorities(AuthorizationRequest request);

		Collection<GrantedAuthority> grantableAuthorities(Authentication result);

	}

	static final class PreAuthenticatedAuthoritiesGranter implements AuthoritiesGranter {

		private final SecurityContextHolderStrategy strategy;

		PreAuthenticatedAuthoritiesGranter(SecurityContextHolderStrategy strategy) {
			this.strategy = strategy;
		}

		@Override
		public Collection<GrantedAuthority> grantableAuthorities(AuthorizationRequest request) {
			return List.of();
		}

		@Override
		public Collection<GrantedAuthority> grantableAuthorities(Authentication result) {
			Authentication current = this.strategy.getContext().getAuthentication();
			if (current == null || !current.isAuthenticated()) {
				return List.of();
			}
			return new HashSet<>(current.getAuthorities());
		}

	}

	static final class CompositeAuthoritiesGranter implements AuthoritiesGranter {

		private final Collection<AuthoritiesGranter> authoritiesGranters;

		CompositeAuthoritiesGranter(AuthoritiesGranter... authorities) {
			this.authoritiesGranters = List.of(authorities);
		}

		@Override
		public Collection<GrantedAuthority> grantableAuthorities(AuthorizationRequest request) {
			Collection<GrantedAuthority> authorities = new HashSet<>();
			for (AuthoritiesGranter granter : this.authoritiesGranters) {
				authorities.addAll(granter.grantableAuthorities(request));
			}
			return authorities;
		}

		@Override
		public Collection<GrantedAuthority> grantableAuthorities(Authentication result) {
			Collection<GrantedAuthority> authorities = new HashSet<>();
			for (AuthoritiesGranter granter : this.authoritiesGranters) {
				authorities.addAll(granter.grantableAuthorities(result));
			}
			return authorities;
		}

	}

	static final class SimpleAuthoritiesGranter implements AuthoritiesGranter {

		private final @Nullable Duration grantingTime;

		private final Collection<String> authorities;

		private Clock clock = Clock.systemUTC();

		SimpleAuthoritiesGranter(String... authorities) {
			this.grantingTime = null;
			this.authorities = List.of(authorities);
		}

		SimpleAuthoritiesGranter(Duration grantingTime, String... authorities) {
			Assert.notEmpty(authorities, "authorities cannot be empty");
			this.grantingTime = grantingTime;
			this.authorities = List.of(authorities);
		}

		@Override
		public Collection<GrantedAuthority> grantableAuthorities(AuthorizationRequest request) {
			Collection<GrantedAuthority> grantable = AuthorityUtils.createAuthorityList(this.authorities);
			Collection<GrantedAuthority> requested = request.getAuthorities();
			grantable.retainAll(requested);
			return grantable;
		}

		@Override
		public Collection<GrantedAuthority> grantableAuthorities(Authentication result) {
			Collection<GrantedAuthority> toGrant = new HashSet<>();
			for (String authority : this.authorities) {
				if (this.grantingTime == null) {
					toGrant.add(new SimpleGrantedAuthority(authority));
				}
				else {
					Instant expiresAt = this.clock.instant().plus(this.grantingTime);
					toGrant.add(new ExpirableGrantedAuthority(authority, expiresAt));
				}
			}
			toGrant.removeAll(result.getAuthorities());
			return toGrant;
		}

		void setClock(Clock clock) {
			this.clock = clock;
		}

	}

	@NullMarked
	static final class AuthoritiesGranterAuthenticationManager implements AuthenticationManager {

		private final AuthenticationManager authenticationManager;

		private final AuthoritiesGranter authoritiesGranter;

		AuthoritiesGranterAuthenticationManager(AuthenticationManager manager, AuthoritiesGranter granter) {
			this.authenticationManager = manager;
			this.authoritiesGranter = granter;
		}

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			Authentication result = this.authenticationManager.authenticate(authentication);
			Assert.isInstanceOf(AuthenticationResult.class, result, "must be of type AuthenticationResult");
			Collection<GrantedAuthority> authorities = this.authoritiesGranter.grantableAuthorities(result);
			return ((AuthenticationResult) result).withGrantedAuthorities((a) -> a.addAll(authorities));
		}

	}

	static final class SimpleAuthorizationEntryPoint implements AuthorizationEntryPoint {

		private final AuthoritiesGranter authoritiesGranter;

		private final AuthenticationEntryPoint authenticationEntryPoint;

		SimpleAuthorizationEntryPoint(AuthenticationEntryPoint authenticationEntryPoint,
				AuthoritiesGranter authoritiesGranter) {
			this.authoritiesGranter = authoritiesGranter;
			this.authenticationEntryPoint = authenticationEntryPoint;
		}

		@Override
		public Collection<GrantedAuthority> grantableAuthorities(AuthorizationRequest request) {
			return this.authoritiesGranter.grantableAuthorities(request);
		}

		@Override
		public void commence(HttpServletRequest request, HttpServletResponse response,
				AuthenticationException authException) throws IOException, ServletException {
			this.authenticationEntryPoint.commence(request, response, authException);
		}

	}

}
