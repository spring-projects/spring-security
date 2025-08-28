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

package org.springframework.security.messaging.access.intercept;

import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.jspecify.annotations.Nullable;

import org.springframework.beans.BeansException;
import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationContextAware;
import org.springframework.core.log.LogMessage;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorityAuthorizationManager;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.SingleResultAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.security.messaging.util.matcher.PathPatternMessageMatcher;
import org.springframework.security.messaging.util.matcher.SimpMessageTypeMatcher;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

public final class MessageMatcherDelegatingAuthorizationManager implements AuthorizationManager<Message<?>> {

	private final Log logger = LogFactory.getLog(getClass());

	private final List<Entry<AuthorizationManager<MessageAuthorizationContext<?>>>> mappings;

	private MessageMatcherDelegatingAuthorizationManager(
			List<Entry<AuthorizationManager<MessageAuthorizationContext<?>>>> mappings) {
		Assert.notEmpty(mappings, "mappings cannot be empty");
		this.mappings = mappings;
	}

	@Override
	public AuthorizationResult authorize(Supplier<? extends @Nullable Authentication> authentication,
			Message<?> message) {
		if (this.logger.isTraceEnabled()) {
			this.logger.trace(LogMessage.format("Authorizing message"));
		}
		for (Entry<AuthorizationManager<MessageAuthorizationContext<?>>> mapping : this.mappings) {
			MessageMatcher<?> matcher = mapping.getMessageMatcher();
			MessageAuthorizationContext<?> authorizationContext = authorizationContext(matcher, message);
			if (authorizationContext != null) {
				AuthorizationManager<MessageAuthorizationContext<?>> manager = mapping.getEntry();
				if (this.logger.isTraceEnabled()) {
					this.logger.trace(LogMessage.format("Checking authorization on message using %s", manager));
				}
				return manager.authorize(authentication, authorizationContext);
			}
		}
		this.logger.trace("Abstaining since did not find matching MessageMatcher");
		return null;
	}

	private MessageAuthorizationContext<?> authorizationContext(MessageMatcher<?> matcher, Message<?> message) {
		MessageMatcher.MatchResult matchResult = matcher.matcher((Message) message);
		if (!matchResult.isMatch()) {
			return null;
		}

		if (!CollectionUtils.isEmpty(matchResult.getVariables())) {
			return new MessageAuthorizationContext<>(message, matchResult.getVariables());
		}

		return new MessageAuthorizationContext<>(message);
	}

	/**
	 * Creates a builder for {@link MessageMatcherDelegatingAuthorizationManager}.
	 * @return the new {@link Builder} instance
	 */
	public static Builder builder() {
		return new Builder();
	}

	/**
	 * A builder for {@link MessageMatcherDelegatingAuthorizationManager}.
	 */
	public static final class Builder implements ApplicationContextAware {

		private final List<Entry<AuthorizationManager<MessageAuthorizationContext<?>>>> mappings = new ArrayList<>();

		private PathPatternMessageMatcher.Builder messageMatcherBuilder = PathPatternMessageMatcher.withDefaults();

		public Builder() {
		}

		/**
		 * Maps any {@link Message} to a security expression.
		 * @return the Expression to associate
		 */
		public Builder.Constraint anyMessage() {
			return matchers(MessageMatcher.ANY_MESSAGE);
		}

		/**
		 * Maps any {@link Message} that has a null SimpMessageHeaderAccessor destination
		 * header (i.e. CONNECT, CONNECT_ACK, HEARTBEAT, UNSUBSCRIBE, DISCONNECT,
		 * DISCONNECT_ACK, OTHER)
		 * @return the Expression to associate
		 */
		public Builder.Constraint nullDestMatcher() {
			return matchers(PathPatternMessageMatcher.NULL_DESTINATION_MATCHER);
		}

		/**
		 * Maps a {@link List} of {@link SimpMessageTypeMatcher} instances.
		 * @param typesToMatch the {@link SimpMessageType} instance to match on
		 * @return the {@link Builder.Constraint} associated to the matchers.
		 */
		public Builder.Constraint simpTypeMatchers(SimpMessageType... typesToMatch) {
			MessageMatcher<?>[] typeMatchers = new MessageMatcher<?>[typesToMatch.length];
			for (int i = 0; i < typesToMatch.length; i++) {
				SimpMessageType typeToMatch = typesToMatch[i];
				typeMatchers[i] = new SimpMessageTypeMatcher(typeToMatch);
			}
			return matchers(typeMatchers);
		}

		/**
		 * Maps a {@link List} of {@link PathPatternMessageMatcher}s instances without
		 * regard to the {@link SimpMessageType}. If no destination is found on the
		 * Message, then the Matcher returns false.
		 * @param patterns the patterns to create {@code MessageMatcher}s from.
		 */
		public Builder.Constraint simpDestMatchers(String... patterns) {
			return simpDestMatchers(null, patterns);
		}

		/**
		 * Maps a {@link List} of {@link PathPatternMessageMatcher}s instances that match
		 * on {@code SimpMessageType.MESSAGE}. If no destination is found on the Message,
		 * then the Matcher returns false.
		 * @param patterns the patterns to create {@code MessageMatcher}s from.
		 */
		public Builder.Constraint simpMessageDestMatchers(String... patterns) {
			return simpDestMatchers(SimpMessageType.MESSAGE, patterns);
		}

		/**
		 * Maps a {@link List} of {@link PathPatternMessageMatcher}s instances that match
		 * on {@code SimpMessageType.SUBSCRIBE}. If no destination is found on the
		 * Message, then the Matcher returns false.
		 * @param patterns the patterns to create {@code MessageMatcher}s from.
		 */
		public Builder.Constraint simpSubscribeDestMatchers(String... patterns) {
			return simpDestMatchers(SimpMessageType.SUBSCRIBE, patterns);
		}

		/**
		 * Maps a {@link List} of {@link PathPatternMessageMatcher} instances. If no
		 * destination is found on the Message, then the Matcher returns false.
		 * @param type the {@link SimpMessageType} to match on. If null, the
		 * {@link SimpMessageType} is not considered for matching.
		 * @param patterns the patterns to create {@code MessageMatcher}s from.
		 * @return the {@link Builder.Constraint} that is associated to the
		 * {@link MessageMatcher}
		 */
		private Builder.Constraint simpDestMatchers(SimpMessageType type, String... patterns) {
			List<MessageMatcher<?>> matchers = new ArrayList<>(patterns.length);
			for (String pattern : patterns) {
				MessageMatcher<Object> matcher = this.messageMatcherBuilder.matcher(type, pattern);
				matchers.add(matcher);
			}
			return new Builder.Constraint(matchers);
		}

		/**
		 * Maps a {@link List} of {@link MessageMatcher} instances to a security
		 * expression.
		 * @param matchers the {@link MessageMatcher} instances to map.
		 * @return The {@link Builder.Constraint} that is associated to the
		 * {@link MessageMatcher} instances
		 */
		public Builder.Constraint matchers(MessageMatcher<?>... matchers) {
			List<MessageMatcher<?>> builders = new ArrayList<>(matchers.length);
			for (MessageMatcher<?> matcher : matchers) {
				builders.add(matcher);
			}
			return new Builder.Constraint(builders);
		}

		public AuthorizationManager<Message<?>> build() {
			return new MessageMatcherDelegatingAuthorizationManager(this.mappings);
		}

		@Override
		public void setApplicationContext(ApplicationContext context) throws BeansException {
			this.messageMatcherBuilder = context.getBeanProvider(PathPatternMessageMatcher.Builder.class)
				.getIfUnique(PathPatternMessageMatcher::withDefaults);
		}

		/**
		 * Represents the security constraint to be applied to the {@link MessageMatcher}
		 * instances.
		 */
		public final class Constraint {

			private final List<? extends MessageMatcher<?>> messageMatchers;

			/**
			 * Creates a new instance
			 * @param messageMatchers the {@link MessageMatcher} instances to map to this
			 * constraint
			 */
			private Constraint(List<? extends MessageMatcher<?>> messageMatchers) {
				Assert.notEmpty(messageMatchers, "messageMatchers cannot be null or empty");
				this.messageMatchers = messageMatchers;
			}

			/**
			 * Shortcut for specifying {@link Message} instances require a particular
			 * role. If you do not want to have "ROLE_" automatically inserted see
			 * {@link #hasAuthority(String)}.
			 * @param role the role to require (i.e. USER, ADMIN, etc). Note, it should
			 * not start with "ROLE_" as this is automatically inserted.
			 * @return the {@link Builder} for further customization
			 */
			public Builder hasRole(String role) {
				return access(AuthorityAuthorizationManager.hasRole(role));
			}

			/**
			 * Shortcut for specifying {@link Message} instances require any of a number
			 * of roles. If you do not want to have "ROLE_" automatically inserted see
			 * {@link #hasAnyAuthority(String...)}
			 * @param roles the roles to require (i.e. USER, ADMIN, etc). Note, it should
			 * not start with "ROLE_" as this is automatically inserted.
			 * @return the {@link Builder} for further customization
			 */
			public Builder hasAnyRole(String... roles) {
				return access(AuthorityAuthorizationManager.hasAnyRole(roles));
			}

			/**
			 * Specify that {@link Message} instances require a particular authority.
			 * @param authority the authority to require (i.e. ROLE_USER, ROLE_ADMIN,
			 * etc).
			 * @return the {@link Builder} for further customization
			 */
			public Builder hasAuthority(String authority) {
				return access(AuthorityAuthorizationManager.hasAuthority(authority));
			}

			/**
			 * Specify that {@link Message} instances requires any of a number
			 * authorities.
			 * @param authorities the requests require at least one of the authorities
			 * (i.e. "ROLE_USER","ROLE_ADMIN" would mean either "ROLE_USER" or
			 * "ROLE_ADMIN" is required).
			 * @return the {@link Builder} for further customization
			 */
			public Builder hasAnyAuthority(String... authorities) {
				return access(AuthorityAuthorizationManager.hasAnyAuthority(authorities));
			}

			/**
			 * Specify that Messages are allowed by anyone.
			 * @return the {@link Builder} for further customization
			 */
			public Builder permitAll() {
				return access(SingleResultAuthorizationManager.permitAll());
			}

			/**
			 * Specify that Messages are not allowed by anyone.
			 * @return the {@link Builder} for further customization
			 */
			public Builder denyAll() {
				return access(SingleResultAuthorizationManager.denyAll());
			}

			/**
			 * Specify that Messages are allowed by any authenticated user.
			 * @return the {@link Builder} for further customization
			 */
			public Builder authenticated() {
				return access(AuthenticatedAuthorizationManager.authenticated());
			}

			/**
			 * Specify that Messages are allowed by users who have authenticated and were
			 * not "remembered".
			 * @return the {@link Builder} for further customization
			 * @since 5.8
			 */
			public Builder fullyAuthenticated() {
				return access(AuthenticatedAuthorizationManager.fullyAuthenticated());
			}

			/**
			 * Specify that Messages are allowed by users that have been remembered.
			 * @return the {@link Builder} for further customization
			 * @since 5.8
			 */
			public Builder rememberMe() {
				return access(AuthenticatedAuthorizationManager.rememberMe());
			}

			/**
			 * Specify that Messages are allowed by anonymous users.
			 * @return the {@link Builder} for further customization
			 * @since 5.8
			 */
			public Builder anonymous() {
				return access(AuthenticatedAuthorizationManager.anonymous());
			}

			/**
			 * Allows specifying that Messages are secured by an arbitrary expression
			 * @param authorizationManager the {@link AuthorizationManager} to secure the
			 * destinations
			 * @return the {@link Builder} for further customization
			 */
			public Builder access(AuthorizationManager<MessageAuthorizationContext<?>> authorizationManager) {
				for (MessageMatcher<?> messageMatcher : this.messageMatchers) {
					Builder.this.mappings.add(new Entry<>(messageMatcher, authorizationManager));
				}
				return Builder.this;
			}

		}

	}

	private static final class Entry<T> {

		private final MessageMatcher<?> messageMatcher;

		private final T entry;

		Entry(MessageMatcher requestMatcher, T entry) {
			this.messageMatcher = requestMatcher;
			this.entry = entry;
		}

		MessageMatcher<?> getMessageMatcher() {
			return this.messageMatcher;
		}

		T getEntry() {
			return this.entry;
		}

	}

}
