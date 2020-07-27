/*
 * Copyright 2002-2014 the original author or authors.
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
package org.springframework.security.test.web.servlet.response;

import java.util.ArrayList;
import java.util.Collection;
import java.util.function.Consumer;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.ResultMatcher;

import static org.springframework.test.util.AssertionErrors.assertEquals;
import static org.springframework.test.util.AssertionErrors.assertTrue;

/**
 * Security related {@link MockMvc} {@link ResultMatcher}s.
 *
 * @author Rob Winch
 * @author Eddú Meléndez
 * @since 4.0
 */
public final class SecurityMockMvcResultMatchers {

	/**
	 * {@link ResultMatcher} that verifies that a specified user is authenticated.
	 * @return the {@link AuthenticatedMatcher} to use
	 */
	public static AuthenticatedMatcher authenticated() {
		return new AuthenticatedMatcher();
	}

	/**
	 * {@link ResultMatcher} that verifies that no user is authenticated.
	 * @return the {@link AuthenticatedMatcher} to use
	 */
	public static ResultMatcher unauthenticated() {
		return new UnAuthenticatedMatcher();
	}

	private abstract static class AuthenticationMatcher<T extends AuthenticationMatcher<T>> implements ResultMatcher {

		protected SecurityContext load(MvcResult result) {
			HttpRequestResponseHolder holder = new HttpRequestResponseHolder(result.getRequest(), result.getResponse());
			SecurityContextRepository repository = WebTestUtils.getSecurityContextRepository(result.getRequest());
			return repository.loadContext(holder);
		}

	}

	/**
	 * A {@link MockMvc} {@link ResultMatcher} that verifies a specific user is associated
	 * to the {@link MvcResult}.
	 *
	 * @author Rob Winch
	 * @since 4.0
	 */
	public static final class AuthenticatedMatcher extends AuthenticationMatcher<AuthenticatedMatcher> {

		private SecurityContext expectedContext;

		private Authentication expectedAuthentication;

		private Object expectedAuthenticationPrincipal;

		private String expectedAuthenticationName;

		private Collection<? extends GrantedAuthority> expectedGrantedAuthorities;

		private Consumer<Authentication> assertAuthentication;

		@Override
		public void match(MvcResult result) {
			SecurityContext context = load(result);

			Authentication auth = context.getAuthentication();

			assertTrue("Authentication should not be null", auth != null);

			if (this.assertAuthentication != null) {
				this.assertAuthentication.accept(auth);
			}

			if (this.expectedContext != null) {
				assertEquals(this.expectedContext + " does not equal " + context, this.expectedContext, context);
			}

			if (this.expectedAuthentication != null) {
				assertEquals(this.expectedAuthentication + " does not equal " + context.getAuthentication(),
						this.expectedAuthentication, context.getAuthentication());
			}

			if (this.expectedAuthenticationPrincipal != null) {
				assertTrue("Authentication cannot be null", context.getAuthentication() != null);
				assertEquals(
						this.expectedAuthenticationPrincipal + " does not equal "
								+ context.getAuthentication().getPrincipal(),
						this.expectedAuthenticationPrincipal, context.getAuthentication().getPrincipal());
			}

			if (this.expectedAuthenticationName != null) {
				assertTrue("Authentication cannot be null", auth != null);
				String name = auth.getName();
				assertEquals(this.expectedAuthenticationName + " does not equal " + name,
						this.expectedAuthenticationName, name);
			}

			if (this.expectedGrantedAuthorities != null) {
				assertTrue("Authentication cannot be null", auth != null);
				Collection<? extends GrantedAuthority> authorities = auth.getAuthorities();
				assertTrue(authorities + " does not contain the same authorities as " + this.expectedGrantedAuthorities,
						authorities.containsAll(this.expectedGrantedAuthorities));
				assertTrue(this.expectedGrantedAuthorities + " does not contain the same authorities as " + authorities,
						this.expectedGrantedAuthorities.containsAll(authorities));
			}
		}

		/**
		 * Allows for any validating the authentication with arbitrary assertions
		 * @param assesrtAuthentication the Consumer which validates the authentication
		 * @return the AuthenticatedMatcher to perform additional assertions
		 */
		public AuthenticatedMatcher withAuthentication(Consumer<Authentication> assesrtAuthentication) {
			this.assertAuthentication = assesrtAuthentication;
			return this;
		}

		/**
		 * Specifies the expected username
		 * @param expected the expected username
		 * @return the {@link AuthenticatedMatcher} for further customization
		 */
		public AuthenticatedMatcher withUsername(String expected) {
			return withAuthenticationName(expected);
		}

		/**
		 * Specifies the expected {@link SecurityContext}
		 * @param expected the expected {@link SecurityContext}
		 * @return the {@link AuthenticatedMatcher} for further customization
		 */
		public AuthenticatedMatcher withSecurityContext(SecurityContext expected) {
			this.expectedContext = expected;
			return this;
		}

		/**
		 * Specifies the expected {@link Authentication}
		 * @param expected the expected {@link Authentication}
		 * @return the {@link AuthenticatedMatcher} for further customization
		 */
		public AuthenticatedMatcher withAuthentication(Authentication expected) {
			this.expectedAuthentication = expected;
			return this;
		}

		/**
		 * Specifies the expected principal
		 * @param expected the expected principal
		 * @return the {@link AuthenticatedMatcher} for further customization
		 */
		public AuthenticatedMatcher withAuthenticationPrincipal(Object expected) {
			this.expectedAuthenticationPrincipal = expected;
			return this;
		}

		/**
		 * Specifies the expected {@link Authentication#getName()}
		 * @param expected the expected {@link Authentication#getName()}
		 * @return the {@link AuthenticatedMatcher} for further customization
		 */
		public AuthenticatedMatcher withAuthenticationName(String expected) {
			this.expectedAuthenticationName = expected;
			return this;
		}

		/**
		 * Specifies the {@link Authentication#getAuthorities()}
		 * @param expected the {@link Authentication#getAuthorities()}
		 * @return the {@link AuthenticatedMatcher} for further customization
		 */
		public AuthenticatedMatcher withAuthorities(Collection<? extends GrantedAuthority> expected) {
			this.expectedGrantedAuthorities = expected;
			return this;
		}

		/**
		 * Specifies the {@link Authentication#getAuthorities()}
		 * @param roles the roles. Each value is automatically prefixed with "ROLE_"
		 * @return the {@link AuthenticatedMatcher} for further customization
		 */
		public AuthenticatedMatcher withRoles(String... roles) {
			Collection<GrantedAuthority> authorities = new ArrayList<>();
			for (String role : roles) {
				authorities.add(new SimpleGrantedAuthority("ROLE_" + role));
			}
			return withAuthorities(authorities);
		}

		AuthenticatedMatcher() {
		}

	}

	/**
	 * A {@link MockMvc} {@link ResultMatcher} that verifies no {@link Authentication} is
	 * associated with the {@link MvcResult}.
	 *
	 * @author Rob Winch
	 * @since 4.0
	 */
	private static final class UnAuthenticatedMatcher extends AuthenticationMatcher<UnAuthenticatedMatcher> {

		private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

		@Override
		public void match(MvcResult result) {
			SecurityContext context = load(result);

			Authentication authentication = context.getAuthentication();
			assertTrue("Expected anonymous Authentication got " + context,
					authentication == null || this.trustResolver.isAnonymous(authentication));
		}

		private UnAuthenticatedMatcher() {
		}

	}

	private SecurityMockMvcResultMatchers() {
	}

}
