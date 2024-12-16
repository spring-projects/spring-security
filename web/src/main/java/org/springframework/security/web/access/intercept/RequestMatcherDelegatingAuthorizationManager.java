/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.access.intercept;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AnyRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} which delegates to a specific
 * {@link AuthorizationManager} based on a {@link RequestMatcher} evaluation.
 *
 * @author Evgeniy Cheban
 * @author Parikshit Dutta
 * @since 5.5
 */
public final class RequestMatcherDelegatingAuthorizationManager implements AuthorizationManager<HttpServletRequest> {

	private static final AuthorizationDecision DENY = new AuthorizationDecision(false);

	private final Log logger = LogFactory.getLog(getClass());

	private final List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings;

	private RequestMatcherDelegatingAuthorizationManager(
			List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings) {
		Assert.notEmpty(mappings, "mappings cannot be empty");
		this.mappings = mappings;
	}

	/**
	 * Delegates to a specific {@link AuthorizationManager} based on a
	 * {@link RequestMatcher} evaluation.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param request the {@link HttpServletRequest} to check
	 * @return an {@link AuthorizationDecision}. If there is no {@link RequestMatcher}
	 * matching the request, or the {@link AuthorizationManager} could not decide, then
	 * null is returned
	 * @deprecated please use {@link #authorize(Supplier, Object)} instead
	 */
	@Deprecated
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Authorizing %s", requestLine(request)));
		}
		for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {

			RequestMatcher matcher = mapping.getRequestMatcher();
			MatchResult matchResult = matcher.matcher(request);
			if (matchResult.isMatch()) {
				AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(
							LogMessage.format("Checking authorization on %s using %s", requestLine(request), manager));
				}
				return manager.check(authentication,
						new RequestAuthorizationContext(request, matchResult.getVariables()));
			}
		}
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.of(() -> "Denying request since did not find matching RequestMatcher"));
		}
		return DENY;
	}

	private static String requestLine(HttpServletRequest request) {
		return request.getMethod() + " " + UrlUtils.buildRequestUrl(request);
	}

	/**
	 * Creates a builder for {@link RequestMatcherDelegatingAuthorizationManager}.
	 * @return the new {@link Builder} instance
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link RequestMatcherDelegatingAuthorizationManager}.
	 */
	public static final class Builder {

		private boolean anyRequestConfigured;

		private final List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings = new ArrayList<>();

		/**
		 * Maps a {@link RequestMatcher} to an {@link AuthorizationManager}.
		 * @param matcher the {@link RequestMatcher} to use
		 * @param manager the {@link AuthorizationManager} to use
		 * @return the {@link Builder} for further customizations
		 */
		public Builder add(RequestMatcher matcher, AuthorizationManager<RequestAuthorizationContext> manager) {
			Assert.state(!this.anyRequestConfigured, "Can't add mappings after anyRequest");
			Assert.notNull(matcher, "matcher cannot be null");
			Assert.notNull(manager, "manager cannot be null");
			this.mappings.add(new RequestMatcherEntry<>(matcher, manager));
			return this;
		}

		/**
		 * Allows to configure the {@link RequestMatcher} to {@link AuthorizationManager}
		 * mappings.
		 * @param mappingsConsumer used to configure the {@link RequestMatcher} to
		 * {@link AuthorizationManager} mappings.
		 * @return the {@link Builder} for further customizations
		 * @since 5.7
		 */
		public Builder mappings(
				Consumer<List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>>> mappingsConsumer) {
			Assert.state(!this.anyRequestConfigured, "Can't configure mappings after anyRequest");
			Assert.notNull(mappingsConsumer, "mappingsConsumer cannot be null");
			mappingsConsumer.accept(this.mappings);
			return this;
		}

		/**
		 * Maps any request.
		 * @return the {@link AuthorizedUrl} for further customizations
		 * @since 6.2
		 */
		public AuthorizedUrl anyRequest() {
			Assert.state(!this.anyRequestConfigured, "Can't configure anyRequest after itself");
			this.anyRequestConfigured = true;
			return new AuthorizedUrl(AnyRequestMatcher.INSTANCE);
		}

		/**
		 * Maps {@link RequestMatcher}s to {@link AuthorizationManager}.
		 * @param matchers the {@link RequestMatcher}s to map
		 * @return the {@link AuthorizedUrl} for further customizations
		 * @since 6.2
		 */
		public AuthorizedUrl requestMatchers(RequestMatcher... matchers) {
			Assert.state(!this.anyRequestConfigured, "Can't configure requestMatchers after anyRequest");
			return new AuthorizedUrl(matchers);
		}

		/**
		 * Creates a {@link RequestMatcherDelegatingAuthorizationManager} instance.
		 * @return the {@link RequestMatcherDelegatingAuthorizationManager} instance
		 */
		public RequestMatcherDelegatingAuthorizationManager build() {
			return new RequestMatcherDelegatingAuthorizationManager(this.mappings);
		}

		/**
		 * An object that allows configuring the {@link AuthorizationManager} for
		 * {@link RequestMatcher}s.
		 *
		 * @author Evgeniy Cheban
		 * @since 6.2
		 */
		public final class AuthorizedUrl {

			private final List<RequestMatcher> matchers;

			private AuthorizedUrl(RequestMatcher... matchers) {
				this(List.of(matchers));
			}

			private AuthorizedUrl(List<RequestMatcher> matchers) {
				this.matchers = matchers;
			}

			/**
			 * Specify that URLs are allowed by anyone.
			 * @return the {@link Builder} for further customizations
			 */
			public Builder permitAll() {
				return access((a, o) -> new AuthorizationDecision(true));
			}

			/**
			 * Specify that URLs are not allowed by anyone.
			 * @return the {@link Builder} for further customizations
			 */
			public Builder denyAll() {
				return access((a, o) -> new AuthorizationDecision(false));
			}

			/**
			 * Specify that URLs are allowed by any authenticated user.
			 * @return the {@link Builder} for further customizations
			 */
			public Builder authenticated() {
				return access(AuthenticatedAuthorizationManager.authenticated());
			}

			/**
			 * Specify that URLs are allowed by users who have authenticated and were not
			 * "remembered".
			 * @return the {@link Builder} for further customization
			 */
			public Builder fullyAuthenticated() {
				return access(AuthenticatedAuthorizationManager.fullyAuthenticated());
			}

			/**
			 * Specify that URLs are allowed by users that have been remembered.
			 * @return the {@link Builder} for further customization
			 */
			public Builder rememberMe() {
				return access(AuthenticatedAuthorizationManager.rememberMe());
			}

			/**
			 * Specify that URLs are allowed by anonymous users.
			 * @return the {@link Builder} for further customization
			 */
			public Builder anonymous() {
				return access(AuthenticatedAuthorizationManager.anonymous());
			}

			/**
			 * Specifies a user requires a role.
			 * @param role the role that should be required which is prepended with ROLE_
			 * automatically (i.e. USER, ADMIN, etc). It should not start with ROLE_
			 * @return {@link Builder} for further customizations
			 */
			public Builder hasRole(String role) {
				return access(AuthorityAuthorizationManager.hasRole(role));
			}

			/**
			 * Specifies that a user requires one of many roles.
			 * @param roles the roles that the user should have at least one of (i.e.
			 * ADMIN, USER, etc). Each role should not start with ROLE_ since it is
			 * automatically prepended already
			 * @return the {@link Builder} for further customizations
			 */
			public Builder hasAnyRole(String... roles) {
				return access(AuthorityAuthorizationManager.hasAnyRole(roles));
			}

			/**
			 * Specifies a user requires an authority.
			 * @param authority the authority that should be required
			 * @return the {@link Builder} for further customizations
			 */
			public Builder hasAuthority(String authority) {
				return access(AuthorityAuthorizationManager.hasAuthority(authority));
			}

			/**
			 * Specifies that a user requires one of many authorities.
			 * @param authorities the authorities that the user should have at least one
			 * of (i.e. ROLE_USER, ROLE_ADMIN, etc)
			 * @return the {@link Builder} for further customizations
			 */
			public Builder hasAnyAuthority(String... authorities) {
				return access(AuthorityAuthorizationManager.hasAnyAuthority(authorities));
			}

			private Builder access(AuthorizationManager<RequestAuthorizationContext> manager) {
				for (RequestMatcher matcher : this.matchers) {
					Builder.this.mappings.add(new RequestMatcherEntry<>(matcher, manager));
				}
				return Builder.this;
			}

		}

	}

}
