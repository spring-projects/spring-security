/*
 *
 *  * Copyright 2002-2017 the original author or authors.
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *      http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package org.springframework.security.test.web.reactive.server;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.security.Principal;
import java.util.Collection;
import java.util.function.Function;
import java.util.function.UnaryOperator;

/**
 * Test utilities for working with Spring Security and
 * {@link org.springframework.test.web.reactive.server.WebTestClient} using
 * {@link org.springframework.test.web.reactive.server.ExchangeMutatorWebFilter}.
 *
 * @author Rob Winch
 * @since 5.0
 */
public class SecurityExchangeMutators {
	/**
	 * Updates the ServerWebExchange to use the provided Principal
	 *
	 * @param principal the principal to use.
	 * @return the {@code Function<ServerWebExchange, ServerWebExchange>} to use
	 */
	public static Function<ServerWebExchange, ServerWebExchange> withPrincipal(Principal principal) {
		return m -> m.mutate().principal(Mono.just(principal)).build();
	}

	/**
	 * Updates the ServerWebExchange to use the provided Authentication as the Principal
	 *
	 * @param authentication the Authentication to use.
	 * @return the {@code Function<ServerWebExchange, ServerWebExchange>} to use
	 */
	public static Function<ServerWebExchange, ServerWebExchange> withAuthentication(Authentication authentication) {
		return withPrincipal(authentication);
	}

	/**
	 * Updates the ServerWebExchange to use the provided UserDetails to create a UsernamePasswordAuthenticationToken as
	 * the Principal
	 *
	 * @param userDetails the UserDetails to use.
	 * @return the {@code Function<ServerWebExchange, ServerWebExchange>} to use
	 */
	public static Function<ServerWebExchange, ServerWebExchange> withUser(UserDetails userDetails) {
		return withAuthentication(new UsernamePasswordAuthenticationToken(userDetails, userDetails.getPassword(), userDetails.getAuthorities()));
	}

	/**
	 * Updates the ServerWebExchange to use a UserDetails to create a UsernamePasswordAuthenticationToken as
	 * the Principal. This uses a default username of "user", password of "password", and granted authorities of
	 * "ROLE_USER".
	 *
	 * @return the {@link UserExchangeMutator} to use
	 */
	public static UserExchangeMutator withUser() {
		return withUser("user");
	}


	/**
	 * Updates the ServerWebExchange to use a UserDetails to create a UsernamePasswordAuthenticationToken as
	 * the Principal. This uses a default password of "password" and granted authorities of
	 * "ROLE_USER".
	 *
	 * @return the {@link UserExchangeMutator} to use
	 */
	public static UserExchangeMutator withUser(String username) {
		return new UserExchangeMutator(username);
	}

	/**
	 * Updates the WebServerExchange using {@code SecurityExchangeMutators#withUser(UserDetails)}. Defaults to use a
	 * password of "password" and granted authorities of "ROLE_USER".
	 */
	public static class UserExchangeMutator implements Function<ServerWebExchange, ServerWebExchange> {
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
		public ServerWebExchange apply(ServerWebExchange serverWebExchange) {
			return withUser(userBuilder.build()).apply(serverWebExchange);
		}
	}
}
