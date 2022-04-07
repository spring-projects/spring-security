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

package org.springframework.security.messaging.access.intercept;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.messaging.Message;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.security.messaging.util.matcher.MessageMatcherEntry;
import org.springframework.security.messaging.util.matcher.SimpDestinationMessageMatcher;
import org.springframework.util.Assert;

/**
 * An {@link AuthorizationManager} which delegates to a specific
 * {@link AuthorizationManager} based on a {@link MessageMatcher} evaluation.
 *
 * @author Josh Cummings
 * @since 5.7
 */
public final class MessageMatcherDelegatingAuthorizationManager implements AuthorizationManager<Message<?>> {

	private final Log logger = LogFactory.getLog(getClass());

	private final List<MessageMatcherEntry<AuthorizationManager<MessageAuthorizationContext<?>>>> mappings;

	private MessageMatcherDelegatingAuthorizationManager(
			List<MessageMatcherEntry<AuthorizationManager<MessageAuthorizationContext<?>>>> mappings) {
		Assert.notEmpty(mappings, "mappings cannot be empty");
		this.mappings = mappings;
	}

	/**
	 * Delegates to a specific {@link AuthorizationManager} based on a
	 * {@link MessageMatcher} evaluation.
	 * @param authentication the {@link Supplier} of the {@link Authentication} to check
	 * @param message the {@link Message} to check
	 * @return an {@link AuthorizationDecision}. If there is no {@link MessageMatcher}
	 * matching the message, or the {@link AuthorizationManager} could not decide, then
	 * null is returned
	 */
	@Override
	public AuthorizationDecision check(Supplier<Authentication> authentication, Message<?> message) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Authorizing message"));
		}
		for (MessageMatcherEntry<AuthorizationManager<MessageAuthorizationContext<?>>> mapping : this.mappings) {
			MessageMatcher<?> matcher = mapping.getMessageMatcher();
			MessageAuthorizationContext<?> authorizationContext = authorizationContext(matcher, message);
			if (authorizationContext != null) {
				AuthorizationManager<MessageAuthorizationContext<?>> manager = mapping.getEntry();
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(LogMessage.format("Checking authorization on message using %s", manager));
				}
				return manager.check(authentication, authorizationContext);
			}
		}
		this.logger.trace("Abstaining since did not find matching MessageMatcher");
		return null;
	}

	private MessageAuthorizationContext<?> authorizationContext(MessageMatcher<?> matcher, Message<?> message) {
		if (!matcher.matches((Message) message)) {
			return null;
		}
		if (matcher instanceof SimpDestinationMessageMatcher) {
			SimpDestinationMessageMatcher simp = (SimpDestinationMessageMatcher) matcher;
			return new MessageAuthorizationContext<>(message, simp.extractPathVariables(message));
		}
		return new MessageAuthorizationContext<>(message);
	}

	/**
	 * Creates a builder for {@link MessageMatcherDelegatingAuthorizationManager}.
	 * @return the new {@link MessageMatcherDelegatingAuthorizationManager.Builder}
	 * instance
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link MessageMatcherDelegatingAuthorizationManager}.
	 */
	public static final class Builder {

		private final List<MessageMatcherEntry<AuthorizationManager<MessageAuthorizationContext<?>>>> mappings = new ArrayList<>();

		/**
		 * Maps a {@link MessageMatcher} to an {@link AuthorizationManager}.
		 * @param matcher the {@link MessageMatcher} to use
		 * @param manager the {@link AuthorizationManager} to use
		 * @return the {@link MessageMatcherDelegatingAuthorizationManager.Builder} for
		 * further customizations
		 */
		public MessageMatcherDelegatingAuthorizationManager.Builder add(MessageMatcher<?> matcher,
				AuthorizationManager<MessageAuthorizationContext<?>> manager) {
			Assert.notNull(matcher, "matcher cannot be null");
			Assert.notNull(manager, "manager cannot be null");
			this.mappings.add(new MessageMatcherEntry<>(matcher, manager));
			return this;
		}

		/**
		 * Creates a {@link MessageMatcherDelegatingAuthorizationManager} instance.
		 * @return the {@link MessageMatcherDelegatingAuthorizationManager} instance
		 */
		public MessageMatcherDelegatingAuthorizationManager build() {
			return new MessageMatcherDelegatingAuthorizationManager(this.mappings);
		}

	}

}
