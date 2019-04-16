/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.test.web.reactive.server;

import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.csrf.CsrfWebFilter;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;

import reactor.core.publisher.Mono;

/**
 * Test utilities for working with Spring Security and
 * {@link org.springframework.test.web.reactive.server.WebTestClient.Builder#apply(WebTestClientConfigurer)}.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityMockServerConfigurers {

	/**
	 * Sets up Spring Security's {@link WebTestClient} test support
	 * @return the MockServerConfigurer to use
	 */
	public static MockServerConfigurer springSecurity() {
		return new MockServerConfigurer() {
			public void beforeServerCreated(WebHttpHandlerBuilder builder) {
				builder.filters( filters -> {
					filters.add(0, new MutatorFilter());
				});
			}
		};
	}

	/**
	 * Updates the ServerWebExchange to use the provided Authentication as the Principal
	 *
	 * @param authentication the Authentication to use.
	 * @return the configurer to use
	 */
	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockAuthentication(Authentication authentication) {
		return (T) new MutatorWebTestClientConfigurer(() -> Mono.just(authentication).map(SecurityContextImpl::new));
	}

	/**
	 * Updates the ServerWebExchange to use the provided UserDetails to create a UsernamePasswordAuthenticationToken as
	 * the Principal
	 *
	 * @param userDetails the UserDetails to use.
	 * @return the configurer to use
	 */
	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockUser(UserDetails userDetails) {
		return mockAuthentication(new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities()));
	}

	/**
	 * Updates the ServerWebExchange to use a UserDetails to create a UsernamePasswordAuthenticationToken as
	 * the Principal. This uses a default username of "user", password of "password", and granted authorities of
	 * "ROLE_USER".
	 *
	 * @return the {@link UserExchangeMutator} to use
	 */
	public static UserExchangeMutator mockUser() {
		return mockUser("user");
	}


	/**
	 * Updates the ServerWebExchange to use a UserDetails to create a UsernamePasswordAuthenticationToken as
	 * the Principal. This uses a default password of "password" and granted authorities of
	 * "ROLE_USER".
	 *
	 * @return the {@link WebTestClientConfigurer} to use
	 */
	public static UserExchangeMutator mockUser(String username) {
		return new UserExchangeMutator(username);
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link JwtAuthenticationToken} for the
	 * {@link Authentication} and a {@link Jwt} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the JWT to be valid.
	 *
	 * @return the {@link JwtMutator} to further configure or use
	 */
	public static JwtMutator mockJwt() {
		return new JwtMutator();
	}

	/**
	 * Updates the ServerWebExchange to establish a {@link SecurityContext} that has a
	 * {@link JwtAuthenticationToken} for the
	 * {@link Authentication} and a {@link Jwt} for the
	 * {@link Authentication#getPrincipal()}. All details are
	 * declarative and do not require the JWT to be valid.
	 *
	 * @param jwt a complete JWT to extract and apply token value, subject, authorities and claims configuration
	 * @return the {@link JwtMutator} to further configure or use
	 */
	public static JwtMutator mockJwt(final Jwt jwt) {
		return mockJwt().jwt(jwt);
	}

	public static CsrfMutator csrf() {
		return new CsrfMutator();
	}

	public static class CsrfMutator implements WebTestClientConfigurer, MockServerConfigurer {

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder,
			@Nullable WebHttpHandlerBuilder httpHandlerBuilder,
			@Nullable ClientHttpConnector connector) {
			CsrfWebFilter filter = new CsrfWebFilter();
			filter.setRequireCsrfProtectionMatcher( e -> ServerWebExchangeMatcher.MatchResult.notMatch());
			httpHandlerBuilder.filters( filters -> filters.add(0, filter));
		}

		@Override
		public void afterConfigureAdded(
			WebTestClient.MockServerSpec<?> serverSpec) {

		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {

		}

		private CsrfMutator() {}
	}

	/**
	 * Updates the WebServerExchange using {@code {@link SecurityMockServerConfigurers#mockUser(UserDetails)}}. Defaults to use a
	 * password of "password" and granted authorities of "ROLE_USER".
	 */
	public static class UserExchangeMutator implements WebTestClientConfigurer, MockServerConfigurer {
		private final User.UserBuilder userBuilder;

		private UserExchangeMutator(String username) {
			this.userBuilder = User.withUsername(username);
			password("password");
			roles("USER");
		}

		/**
		 * Specifies the password to use. Default is "password".
		 * @param password the password to use
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator password(String password) {
			this.userBuilder.password(password);
			return this;
		}

		/**
		 * Specifies the roles to use. Default is "USER". This is similar to authorities except each role is
		 * automatically prefixed with "ROLE_USER".
		 *
		 * @param roles the roles to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator roles(String... roles) {
			this.userBuilder.roles(roles);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 *
		 * @param authorities the authorities to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator authorities(GrantedAuthority... authorities) {
			this.userBuilder.authorities(authorities);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 *
		 * @param authorities the authorities to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator authorities(Collection<? extends GrantedAuthority> authorities) {
			this.userBuilder.authorities(authorities);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 * @param authorities the authorities to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator authorities(String... authorities) {
			this.userBuilder.authorities(authorities);
			return this;
		}

		public UserExchangeMutator accountExpired(boolean accountExpired) {
			this.userBuilder.accountExpired(accountExpired);
			return this;
		}

		public UserExchangeMutator accountLocked(boolean accountLocked) {
			this.userBuilder.accountLocked(accountLocked);
			return this;
		}

		public UserExchangeMutator credentialsExpired(boolean credentialsExpired) {
			this.userBuilder.credentialsExpired(credentialsExpired);
			return this;
		}

		public UserExchangeMutator disabled(boolean disabled) {
			this.userBuilder.disabled(disabled);
			return this;
		}

		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {
			configurer().beforeServerCreated(builder);
		}

		@Override
		public void afterConfigureAdded(WebTestClient.MockServerSpec<?> serverSpec) {
			configurer().afterConfigureAdded(serverSpec);
		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder, @Nullable WebHttpHandlerBuilder webHttpHandlerBuilder, @Nullable ClientHttpConnector clientHttpConnector) {
			configurer().afterConfigurerAdded(builder, webHttpHandlerBuilder, clientHttpConnector);
		}

		private <T extends WebTestClientConfigurer & MockServerConfigurer> T configurer() {
			return mockUser(this.userBuilder.build());
		}
	}

	private static class MutatorWebTestClientConfigurer implements WebTestClientConfigurer, MockServerConfigurer {
		private final Supplier<Mono<SecurityContext>> context;

		private MutatorWebTestClientConfigurer(Supplier<Mono<SecurityContext>> context) {
			this.context = context;
		}
		@Override
		public void beforeServerCreated(WebHttpHandlerBuilder builder) {
			builder.filters(addSetupMutatorFilter());
		}

		@Override
		public void afterConfigurerAdded(WebTestClient.Builder builder, @Nullable WebHttpHandlerBuilder webHttpHandlerBuilder, @Nullable ClientHttpConnector clientHttpConnector) {
			webHttpHandlerBuilder.filters(addSetupMutatorFilter());
		}

		private Consumer<List<WebFilter>> addSetupMutatorFilter() {
			return filters -> filters.add(0, new SetupMutatorFilter(this.context));
		}
	}

	private static class SetupMutatorFilter implements WebFilter {
		private final Supplier<Mono<SecurityContext>> context;

		private SetupMutatorFilter(Supplier<Mono<SecurityContext>> context) {
			this.context = context;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain webFilterChain) {
			exchange.getAttributes().computeIfAbsent(MutatorFilter.ATTRIBUTE_NAME, key -> this.context);
			return webFilterChain.filter(exchange);
		}
	}

	private static class MutatorFilter implements WebFilter {
		public static final String ATTRIBUTE_NAME = "context";

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain webFilterChain) {
			Supplier<Mono<SecurityContext>> context = exchange.getAttribute(ATTRIBUTE_NAME);
			if (context != null) {
				exchange.getAttributes().remove(ATTRIBUTE_NAME);
				return webFilterChain.filter(exchange)
					.subscriberContext(ReactiveSecurityContextHolder.withSecurityContext(context.get()));
			}
			return webFilterChain.filter(exchange);
		}
	}
}
