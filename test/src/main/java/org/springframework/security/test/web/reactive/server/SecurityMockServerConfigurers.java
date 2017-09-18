/*
 *
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
 *
 */

package org.springframework.security.test.web.reactive.server;

import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.lang.Nullable;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.test.context.TestSecurityContextHolder;
import org.springframework.test.web.reactive.server.MockServerConfigurer;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.reactive.server.WebTestClientConfigurer;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.server.adapter.WebHttpHandlerBuilder;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.Collection;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Supplier;

/**
 * Test utilities for working with Spring Security and
 * {{@link org.springframework.test.web.reactive.server.WebTestClient.Builder#apply(WebTestClientConfigurer)}}.
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
					filters.add(0, new SetupMutatorFilter(createMutator( () -> TestSecurityContextHolder.getContext().getAuthentication())));
				});
			}
		};
	}

	/**
	 * Updates the ServerWebExchange to use the provided Principal
	 *
	 * @param principal the principal to use.
	 * @return the {@link WebTestClientConfigurer} to use
	 */
	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockPrincipal(Principal principal) {
		return (T) new MutatorWebTestClientConfigurer(createMutator(() -> principal));
	}

	/**
	 * Updates the ServerWebExchange to use the provided Authentication as the Principal
	 *
	 * @param authentication the Authentication to use.
	 * @return the {@link WebTestClientConfigurer}} to use
	 */
	public static <T extends WebTestClientConfigurer & MockServerConfigurer> T mockAuthentication(Authentication authentication) {
		return mockPrincipal(authentication);
	}

	/**
	 * Updates the ServerWebExchange to use the provided UserDetails to create a UsernamePasswordAuthenticationToken as
	 * the Principal
	 *
	 * @param userDetails the UserDetails to use.
	 * @return the {@link WebTestClientConfigurer} to use
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

	private static Function<ServerWebExchange, ServerWebExchange> createMutator(Supplier<Principal> principal) {
		return m -> principal.get() == null ? m : m.mutate().principal(Mono.just(principal.get())).build();
	}

	/**
	 * Updates the WebServerExchange using {@code {@link SecurityMockServerConfigurers#mockUser(UserDetails)}. Defaults to use a
	 * password of "password" and granted authorities of "ROLE_USER".
	 */
	public static class UserExchangeMutator implements WebTestClientConfigurer, MockServerConfigurer {
		private final User.UserBuilder userBuilder;

		private UserExchangeMutator(String username) {
			userBuilder = User.withUsername(username);
			password("password");
			roles("USER");
		}

		/**
		 * Specifies the password to use. Default is "password".
		 * @param password the password to use
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator password(String password) {
			userBuilder.password(password);
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
			userBuilder.roles(roles);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 *
		 * @param authorities the authorities to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator authorities(GrantedAuthority... authorities) {
			userBuilder.authorities(authorities);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 *
		 * @param authorities the authorities to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator authorities(Collection<? extends GrantedAuthority> authorities) {
			userBuilder.authorities(authorities);
			return this;
		}

		/**
		 * Specifies the {@code GrantedAuthority}s to use. Default is "ROLE_USER".
		 * @param authorities the authorities to use.
		 * @return the UserExchangeMutator
		 */
		public UserExchangeMutator authorities(String... authorities) {
			userBuilder.authorities(authorities);
			return this;
		}

		public UserExchangeMutator accountExpired(boolean accountExpired) {
			userBuilder.accountExpired(accountExpired);
			return this;
		}

		public UserExchangeMutator accountLocked(boolean accountLocked) {
			userBuilder.accountLocked(accountLocked);
			return this;
		}

		public UserExchangeMutator credentialsExpired(boolean credentialsExpired) {
			userBuilder.credentialsExpired(credentialsExpired);
			return this;
		}

		public UserExchangeMutator disabled(boolean disabled) {
			userBuilder.disabled(disabled);
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
			return mockUser(userBuilder.build());
		}
	}

	private static class MutatorWebTestClientConfigurer implements WebTestClientConfigurer, MockServerConfigurer {
		private final Function<ServerWebExchange, ServerWebExchange> mutator;

		private MutatorWebTestClientConfigurer(Function<ServerWebExchange, ServerWebExchange> mutator) {
			this.mutator = mutator;
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
			return filters -> filters.add(0, new SetupMutatorFilter(mutator));
		}
	}

	private static class SetupMutatorFilter implements WebFilter {
		private final Function<ServerWebExchange, ServerWebExchange> mutator;

		private SetupMutatorFilter(Function<ServerWebExchange, ServerWebExchange> mutator) {
			this.mutator = mutator;
		}

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain webFilterChain) {
			exchange.getAttributes().computeIfAbsent(MutatorFilter.ATTRIBUTE_NAME, key -> mutator);
			return webFilterChain.filter(exchange);
		}
	}

	private static class MutatorFilter implements WebFilter {

		public static final String ATTRIBUTE_NAME = "mutator";

		@Override
		public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain webFilterChain) {
			Function<ServerWebExchange, ServerWebExchange> mutator = exchange.getAttribute(ATTRIBUTE_NAME);
			if(mutator != null) {
				exchange.getAttributes().remove(ATTRIBUTE_NAME);
				exchange = mutator.apply(exchange);
			}
			return webFilterChain.filter(exchange);
		}
	}
}
