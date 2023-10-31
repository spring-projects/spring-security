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

package org.springframework.security.web.access.intercept;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Consumer;
import java.util.function.Supplier;

import jakarta.servlet.http.HttpServletRequest;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
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
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, HttpServletRequest request) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Authorizing %s", request));
		}
		for (RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>> mapping : this.mappings) {

			RequestMatcher matcher = mapping.getRequestMatcher();
			MatchResult matchResult = matcher.matcher(request);
			if (matchResult.isMatch()) {
				AuthorizationManager<RequestAuthorizationContext> manager = mapping.getEntry();
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(LogMessage.format("Checking authorization on %s using %s", request, manager));
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

		private final List<RequestMatcherEntry<AuthorizationManager<RequestAuthorizationContext>>> mappings = new ArrayList<>();

		/**
		 * Maps a {@link RequestMatcher} to an {@link AuthorizationManager}.
		 * @param matcher the {@link RequestMatcher} to use
		 * @param manager the {@link AuthorizationManager} to use
		 * @return the {@link Builder} for further customizations
		 */
		public Builder add(RequestMatcher matcher, AuthorizationManager<RequestAuthorizationContext> manager) {
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
			Assert.notNull(mappingsConsumer, "mappingsConsumer cannot be null");
			mappingsConsumer.accept(this.mappings);
			return this;
		}

		/**
		 * Creates a {@link RequestMatcherDelegatingAuthorizationManager} instance.
		 * @return the {@link RequestMatcherDelegatingAuthorizationManager} instance
		 */
		public RequestMatcherDelegatingAuthorizationManager build() {
			return new RequestMatcherDelegatingAuthorizationManager(this.mappings);
		}

	}

}
