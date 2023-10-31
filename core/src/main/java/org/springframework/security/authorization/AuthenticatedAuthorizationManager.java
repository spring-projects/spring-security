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

package org.springframework.security.authorization;

import java.util.function.Supplier;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} that determines if the current user is authenticated.
 *
 * @param <T> the type of object authorization is being performed against. This does not.
 * @author Evgeniy Cheban
 * @since 5.5
 */
public final class AuthenticatedAuthorizationManager<T> implements AuthorizationManager<T> {

	private final AbstractAuthorizationStrategy authorizationStrategy;

	/**
	 * Creates an instance that determines if the current user is authenticated, this is
	 * the same as calling {@link #authenticated()} factory method.
	 *
	 * @since 5.8
	 * @see #authenticated()
	 * @see #fullyAuthenticated()
	 * @see #rememberMe()
	 * @see #anonymous()
	 */
	public AuthenticatedAuthorizationManager() {
		this(new AuthenticatedAuthorizationStrategy());
	}

	private AuthenticatedAuthorizationManager(AbstractAuthorizationStrategy authorizationStrategy) {
		this.authorizationStrategy = authorizationStrategy;
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. Default is
	 * {@link AuthenticationTrustResolverImpl}. Cannot be null.
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use
	 * @since 5.8
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		this.authorizationStrategy.setTrustResolver(trustResolver);
	}

	/**
	 * Creates an instance of {@link AuthenticatedAuthorizationManager}.
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 */
	public static <T> AuthenticatedAuthorizationManager<T> authenticated() {
		return new AuthenticatedAuthorizationManager<>();
	}

	/**
	 * Creates an instance of {@link AuthenticatedAuthorizationManager} that determines if
	 * the {@link Authentication} is authenticated without using remember me.
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 * @since 5.8
	 */
	public static <T> AuthenticatedAuthorizationManager<T> fullyAuthenticated() {
		return new AuthenticatedAuthorizationManager<>(new FullyAuthenticatedAuthorizationStrategy());
	}

	/**
	 * Creates an instance of {@link AuthenticatedAuthorizationManager} that determines if
	 * the {@link Authentication} is authenticated using remember me.
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 * @since 5.8
	 */
	public static <T> AuthenticatedAuthorizationManager<T> rememberMe() {
		return new AuthenticatedAuthorizationManager<>(new RememberMeAuthorizationStrategy());
	}

	/**
	 * Creates an instance of {@link AuthenticatedAuthorizationManager} that determines if
	 * the {@link Authentication} is anonymous.
	 * @param <T> the type of object being authorized
	 * @return the new instance
	 * @since 5.8
	 */
	public static <T> AuthenticatedAuthorizationManager<T> anonymous() {
		return new AuthenticatedAuthorizationManager<>(new AnonymousAuthorizationStrategy());
	}

	/**
	 * Determines if the current user is authorized according to the given strategy.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param object the {@link T} object to check
	 * @return an {@link AuthorizationDecision}
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, T object) {
		boolean granted = this.authorizationStrategy.isGranted(authentication.get());
		return new AuthorizationDecision(granted);
	}

	private abstract static class AbstractAuthorizationStrategy {

		AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

		private void setTrustResolver(AuthenticationTrustResolver trustResolver) {
			Assert.notNull(trustResolver, "trustResolver cannot be null");
			this.trustResolver = trustResolver;
		}

		abstract boolean isGranted(Authentication authentication);

	}

	private static class AuthenticatedAuthorizationStrategy extends AbstractAuthorizationStrategy {

		@Override
		boolean isGranted(Authentication authentication) {
			return authentication != null && !this.trustResolver.isAnonymous(authentication)
					&& authentication.isAuthenticated();
		}

	}

	private static final class FullyAuthenticatedAuthorizationStrategy extends AuthenticatedAuthorizationStrategy {

		@Override
		boolean isGranted(Authentication authentication) {
			return super.isGranted(authentication) && !this.trustResolver.isRememberMe(authentication);
		}

	}

	private static final class AnonymousAuthorizationStrategy extends AbstractAuthorizationStrategy {

		@Override
		boolean isGranted(Authentication authentication) {
			return this.trustResolver.isAnonymous(authentication);
		}

	}

	private static final class RememberMeAuthorizationStrategy extends AbstractAuthorizationStrategy {

		@Override
		boolean isGranted(Authentication authentication) {
			return this.trustResolver.isRememberMe(authentication);
		}

	}

}
