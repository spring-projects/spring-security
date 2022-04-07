/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.config.annotation.web.messaging;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.config.annotation.web.configurers.RememberMeConfigurer;
import org.springframework.security.messaging.access.expression.DefaultMessageSecurityExpressionHandler;
import org.springframework.security.messaging.access.expression.ExpressionBasedMessageSecurityMetadataSourceFactory;
import org.springframework.security.messaging.access.intercept.MessageSecurityMetadataSource;
import org.springframework.security.messaging.util.matcher.MessageMatcher;
import org.springframework.security.messaging.util.matcher.SimpDestinationMessageMatcher;
import org.springframework.security.messaging.util.matcher.SimpMessageTypeMatcher;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.PathMatcher;
import org.springframework.util.StringUtils;

/**
 * Allows mapping security constraints using {@link MessageMatcher} to the security
 * expressions.
 *
 * @author Rob Winch
 * @since 4.0
 */
public class MessageSecurityMetadataSourceRegistry {

	private static final String permitAll = "permitAll";

	private static final String denyAll = "denyAll";

	private static final String anonymous = "anonymous";

	private static final String authenticated = "authenticated";

	private static final String fullyAuthenticated = "fullyAuthenticated";

	private static final String rememberMe = "rememberMe";

	private SecurityExpressionHandler<Message<Object>> expressionHandler = new DefaultMessageSecurityExpressionHandler<>();

	private final LinkedHashMap<MatcherBuilder, String> matcherToExpression = new LinkedHashMap<>();

	private DelegatingPathMatcher pathMatcher = new DelegatingPathMatcher();

	private boolean defaultPathMatcher = true;

	/**
	 * Maps any {@link Message} to a security expression.
	 * @return the Expression to associate
	 */
	public Constraint anyMessage() {
		return matchers(MessageMatcher.ANY_MESSAGE);
	}

	/**
	 * Maps any {@link Message} that has a null SimpMessageHeaderAccessor destination
	 * header (i.e. CONNECT, CONNECT_ACK, HEARTBEAT, UNSUBSCRIBE, DISCONNECT,
	 * DISCONNECT_ACK, OTHER)
	 * @return the Expression to associate
	 */
	public Constraint nullDestMatcher() {
		return matchers(SimpDestinationMessageMatcher.NULL_DESTINATION_MATCHER);
	}

	/**
	 * Maps a {@link List} of {@link SimpDestinationMessageMatcher} instances.
	 * @param typesToMatch the {@link SimpMessageType} instance to match on
	 * @return the {@link Constraint} associated to the matchers.
	 */
	public Constraint simpTypeMatchers(SimpMessageType... typesToMatch) {
		MessageMatcher<?>[] typeMatchers = new MessageMatcher<?>[typesToMatch.length];
		for (int i = 0; i < typesToMatch.length; i++) {
			SimpMessageType typeToMatch = typesToMatch[i];
			typeMatchers[i] = new SimpMessageTypeMatcher(typeToMatch);
		}
		return matchers(typeMatchers);
	}

	/**
	 * Maps a {@link List} of {@link SimpDestinationMessageMatcher} instances without
	 * regard to the {@link SimpMessageType}. If no destination is found on the Message,
	 * then the Matcher returns false.
	 * @param patterns the patterns to create
	 * {@link org.springframework.security.messaging.util.matcher.SimpDestinationMessageMatcher}
	 * from. Uses
	 * {@link MessageSecurityMetadataSourceRegistry#simpDestPathMatcher(PathMatcher)} .
	 * @return the {@link Constraint} that is associated to the {@link MessageMatcher}
	 * @see MessageSecurityMetadataSourceRegistry#simpDestPathMatcher(PathMatcher)
	 */
	public Constraint simpDestMatchers(String... patterns) {
		return simpDestMatchers(null, patterns);
	}

	/**
	 * Maps a {@link List} of {@link SimpDestinationMessageMatcher} instances that match
	 * on {@code SimpMessageType.MESSAGE}. If no destination is found on the Message, then
	 * the Matcher returns false.
	 * @param patterns the patterns to create
	 * {@link org.springframework.security.messaging.util.matcher.SimpDestinationMessageMatcher}
	 * from. Uses
	 * {@link MessageSecurityMetadataSourceRegistry#simpDestPathMatcher(PathMatcher)}.
	 * @return the {@link Constraint} that is associated to the {@link MessageMatcher}
	 * @see MessageSecurityMetadataSourceRegistry#simpDestPathMatcher(PathMatcher)
	 */
	public Constraint simpMessageDestMatchers(String... patterns) {
		return simpDestMatchers(SimpMessageType.MESSAGE, patterns);
	}

	/**
	 * Maps a {@link List} of {@link SimpDestinationMessageMatcher} instances that match
	 * on {@code SimpMessageType.SUBSCRIBE}. If no destination is found on the Message,
	 * then the Matcher returns false.
	 * @param patterns the patterns to create
	 * {@link org.springframework.security.messaging.util.matcher.SimpDestinationMessageMatcher}
	 * from. Uses
	 * {@link MessageSecurityMetadataSourceRegistry#simpDestPathMatcher(PathMatcher)}.
	 * @return the {@link Constraint} that is associated to the {@link MessageMatcher}
	 * @see MessageSecurityMetadataSourceRegistry#simpDestPathMatcher(PathMatcher)
	 */
	public Constraint simpSubscribeDestMatchers(String... patterns) {
		return simpDestMatchers(SimpMessageType.SUBSCRIBE, patterns);
	}

	/**
	 * Maps a {@link List} of {@link SimpDestinationMessageMatcher} instances. If no
	 * destination is found on the Message, then the Matcher returns false.
	 * @param type the {@link SimpMessageType} to match on. If null, the
	 * {@link SimpMessageType} is not considered for matching.
	 * @param patterns the patterns to create
	 * {@link org.springframework.security.messaging.util.matcher.SimpDestinationMessageMatcher}
	 * from. Uses
	 * {@link MessageSecurityMetadataSourceRegistry#simpDestPathMatcher(PathMatcher)}.
	 * @return the {@link Constraint} that is associated to the {@link MessageMatcher}
	 * @see MessageSecurityMetadataSourceRegistry#simpDestPathMatcher(PathMatcher)
	 */
	private Constraint simpDestMatchers(SimpMessageType type, String... patterns) {
		List<MatcherBuilder> matchers = new ArrayList<>(patterns.length);
		for (String pattern : patterns) {
			matchers.add(new PathMatcherMessageMatcherBuilder(pattern, type));
		}
		return new Constraint(matchers);
	}

	/**
	 * The {@link PathMatcher} to be used with the
	 * {@link MessageSecurityMetadataSourceRegistry#simpDestMatchers(String...)}. The
	 * default is to use the default constructor of {@link AntPathMatcher}.
	 * @param pathMatcher the {@link PathMatcher} to use. Cannot be null.
	 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
	 * customization.
	 */
	public MessageSecurityMetadataSourceRegistry simpDestPathMatcher(PathMatcher pathMatcher) {
		Assert.notNull(pathMatcher, "pathMatcher cannot be null");
		this.pathMatcher.setPathMatcher(pathMatcher);
		this.defaultPathMatcher = false;
		return this;
	}

	/**
	 * Determines if the {@link #simpDestPathMatcher(PathMatcher)} has been explicitly
	 * set.
	 * @return true if {@link #simpDestPathMatcher(PathMatcher)} has been explicitly set,
	 * else false.
	 */
	protected boolean isSimpDestPathMatcherConfigured() {
		return !this.defaultPathMatcher;
	}

	/**
	 * Maps a {@link List} of {@link MessageMatcher} instances to a security expression.
	 * @param matchers the {@link MessageMatcher} instances to map.
	 * @return The {@link Constraint} that is associated to the {@link MessageMatcher}
	 * instances
	 */
	public Constraint matchers(MessageMatcher<?>... matchers) {
		List<MatcherBuilder> builders = new ArrayList<>(matchers.length);
		for (MessageMatcher<?> matcher : matchers) {
			builders.add(new PreBuiltMatcherBuilder(matcher));
		}
		return new Constraint(builders);
	}

	/**
	 * The {@link SecurityExpressionHandler} to be used. The default is to use
	 * {@link DefaultMessageSecurityExpressionHandler}.
	 * @param expressionHandler the {@link SecurityExpressionHandler} to use. Cannot be
	 * null.
	 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
	 * customization.
	 */
	public MessageSecurityMetadataSourceRegistry expressionHandler(
			SecurityExpressionHandler<Message<Object>> expressionHandler) {
		Assert.notNull(expressionHandler, "expressionHandler cannot be null");
		this.expressionHandler = expressionHandler;
		return this;
	}

	/**
	 * Allows subclasses to create creating a {@link MessageSecurityMetadataSource}.
	 *
	 * <p>
	 * This is not exposed so as not to confuse users of the API, which should never
	 * invoke this method.
	 * </p>
	 * @return the {@link MessageSecurityMetadataSource} to use
	 */
	protected MessageSecurityMetadataSource createMetadataSource() {
		LinkedHashMap<MessageMatcher<?>, String> matcherToExpression = new LinkedHashMap<>();
		for (Map.Entry<MatcherBuilder, String> entry : this.matcherToExpression.entrySet()) {
			matcherToExpression.put(entry.getKey().build(), entry.getValue());
		}
		return ExpressionBasedMessageSecurityMetadataSourceFactory
				.createExpressionMessageMetadataSource(matcherToExpression, this.expressionHandler);
	}

	/**
	 * Allows determining if a mapping was added.
	 *
	 * <p>
	 * This is not exposed so as not to confuse users of the API, which should never need
	 * to invoke this method.
	 * </p>
	 * @return true if a mapping was added, else false
	 */
	protected boolean containsMapping() {
		return !this.matcherToExpression.isEmpty();
	}

	private static String hasAnyRole(String... authorities) {
		String anyAuthorities = StringUtils.arrayToDelimitedString(authorities, "','ROLE_");
		return "hasAnyRole('ROLE_" + anyAuthorities + "')";
	}

	private static String hasRole(String role) {
		Assert.notNull(role, "role cannot be null");
		if (role.startsWith("ROLE_")) {
			throw new IllegalArgumentException(
					"role should not start with 'ROLE_' since it is automatically inserted. Got '" + role + "'");
		}
		return "hasRole('ROLE_" + role + "')";
	}

	private static String hasAuthority(String authority) {
		return "hasAuthority('" + authority + "')";
	}

	private static String hasAnyAuthority(String... authorities) {
		String anyAuthorities = StringUtils.arrayToDelimitedString(authorities, "','");
		return "hasAnyAuthority('" + anyAuthorities + "')";
	}

	/**
	 * Represents the security constraint to be applied to the {@link MessageMatcher}
	 * instances.
	 */
	public final class Constraint {

		private final List<? extends MatcherBuilder> messageMatchers;

		/**
		 * Creates a new instance
		 * @param messageMatchers the {@link MessageMatcher} instances to map to this
		 * constraint
		 */
		private Constraint(List<? extends MatcherBuilder> messageMatchers) {
			Assert.notEmpty(messageMatchers, "messageMatchers cannot be null or empty");
			this.messageMatchers = messageMatchers;
		}

		/**
		 * Shortcut for specifying {@link Message} instances require a particular role. If
		 * you do not want to have "ROLE_" automatically inserted see
		 * {@link #hasAuthority(String)}.
		 * @param role the role to require (i.e. USER, ADMIN, etc). Note, it should not
		 * start with "ROLE_" as this is automatically inserted.
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 */
		public MessageSecurityMetadataSourceRegistry hasRole(String role) {
			return access(MessageSecurityMetadataSourceRegistry.hasRole(role));
		}

		/**
		 * Shortcut for specifying {@link Message} instances require any of a number of
		 * roles. If you do not want to have "ROLE_" automatically inserted see
		 * {@link #hasAnyAuthority(String...)}
		 * @param roles the roles to require (i.e. USER, ADMIN, etc). Note, it should not
		 * start with "ROLE_" as this is automatically inserted.
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 */
		public MessageSecurityMetadataSourceRegistry hasAnyRole(String... roles) {
			return access(MessageSecurityMetadataSourceRegistry.hasAnyRole(roles));
		}

		/**
		 * Specify that {@link Message} instances require a particular authority.
		 * @param authority the authority to require (i.e. ROLE_USER, ROLE_ADMIN, etc).
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 */
		public MessageSecurityMetadataSourceRegistry hasAuthority(String authority) {
			return access(MessageSecurityMetadataSourceRegistry.hasAuthority(authority));
		}

		/**
		 * Specify that {@link Message} instances requires any of a number authorities.
		 * @param authorities the requests require at least one of the authorities (i.e.
		 * "ROLE_USER","ROLE_ADMIN" would mean either "ROLE_USER" or "ROLE_ADMIN" is
		 * required).
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 */
		public MessageSecurityMetadataSourceRegistry hasAnyAuthority(String... authorities) {
			return access(MessageSecurityMetadataSourceRegistry.hasAnyAuthority(authorities));
		}

		/**
		 * Specify that Messages are allowed by anyone.
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 */
		public MessageSecurityMetadataSourceRegistry permitAll() {
			return access(permitAll);
		}

		/**
		 * Specify that Messages are allowed by anonymous users.
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 */
		public MessageSecurityMetadataSourceRegistry anonymous() {
			return access(anonymous);
		}

		/**
		 * Specify that Messages are allowed by users that have been remembered.
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 * @see RememberMeConfigurer
		 */
		public MessageSecurityMetadataSourceRegistry rememberMe() {
			return access(rememberMe);
		}

		/**
		 * Specify that Messages are not allowed by anyone.
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 */
		public MessageSecurityMetadataSourceRegistry denyAll() {
			return access(denyAll);
		}

		/**
		 * Specify that Messages are allowed by any authenticated user.
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 */
		public MessageSecurityMetadataSourceRegistry authenticated() {
			return access(authenticated);
		}

		/**
		 * Specify that Messages are allowed by users who have authenticated and were not
		 * "remembered".
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 * @see RememberMeConfigurer
		 */
		public MessageSecurityMetadataSourceRegistry fullyAuthenticated() {
			return access(fullyAuthenticated);
		}

		/**
		 * Allows specifying that Messages are secured by an arbitrary expression
		 * @param attribute the expression to secure the URLs (i.e. "hasRole('ROLE_USER')
		 * and hasRole('ROLE_SUPER')")
		 * @return the {@link MessageSecurityMetadataSourceRegistry} for further
		 * customization
		 */
		public MessageSecurityMetadataSourceRegistry access(String attribute) {
			for (MatcherBuilder messageMatcher : this.messageMatchers) {
				MessageSecurityMetadataSourceRegistry.this.matcherToExpression.put(messageMatcher, attribute);
			}
			return MessageSecurityMetadataSourceRegistry.this;
		}

	}

	private static final class PreBuiltMatcherBuilder implements MatcherBuilder {

		private MessageMatcher<?> matcher;

		private PreBuiltMatcherBuilder(MessageMatcher<?> matcher) {
			this.matcher = matcher;
		}

		@Override
		public MessageMatcher<?> build() {
			return this.matcher;
		}

	}

	private final class PathMatcherMessageMatcherBuilder implements MatcherBuilder {

		private final String pattern;

		private final SimpMessageType type;

		private PathMatcherMessageMatcherBuilder(String pattern, SimpMessageType type) {
			this.pattern = pattern;
			this.type = type;
		}

		@Override
		public MessageMatcher<?> build() {
			if (this.type == null) {
				return new SimpDestinationMessageMatcher(this.pattern,
						MessageSecurityMetadataSourceRegistry.this.pathMatcher);
			}
			if (SimpMessageType.MESSAGE == this.type) {
				return SimpDestinationMessageMatcher.createMessageMatcher(this.pattern,
						MessageSecurityMetadataSourceRegistry.this.pathMatcher);
			}
			if (SimpMessageType.SUBSCRIBE == this.type) {
				return SimpDestinationMessageMatcher.createSubscribeMatcher(this.pattern,
						MessageSecurityMetadataSourceRegistry.this.pathMatcher);
			}
			throw new IllegalStateException(this.type + " is not supported since it does not have a destination");
		}

	}

	private interface MatcherBuilder {

		MessageMatcher<?> build();

	}

	static class DelegatingPathMatcher implements PathMatcher {

		private PathMatcher delegate = new AntPathMatcher();

		@Override
		public boolean isPattern(String path) {
			return this.delegate.isPattern(path);
		}

		@Override
		public boolean match(String pattern, String path) {
			return this.delegate.match(pattern, path);
		}

		@Override
		public boolean matchStart(String pattern, String path) {
			return this.delegate.matchStart(pattern, path);
		}

		@Override
		public String extractPathWithinPattern(String pattern, String path) {
			return this.delegate.extractPathWithinPattern(pattern, path);
		}

		@Override
		public Map<String, String> extractUriTemplateVariables(String pattern, String path) {
			return this.delegate.extractUriTemplateVariables(pattern, path);
		}

		@Override
		public Comparator<String> getPatternComparator(String path) {
			return this.delegate.getPatternComparator(path);
		}

		@Override
		public String combine(String pattern1, String pattern2) {
			return this.delegate.combine(pattern1, pattern2);
		}

		void setPathMatcher(PathMatcher pathMatcher) {
			this.delegate = pathMatcher;
		}

	}

}
