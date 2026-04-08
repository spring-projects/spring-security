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

package org.springframework.security.messaging.util.matcher;

import java.util.Collections;

import org.jspecify.annotations.Nullable;

import org.springframework.http.server.PathContainer;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.security.messaging.access.intercept.MessageAuthorizationContext;
import org.springframework.util.Assert;
import org.springframework.web.util.pattern.PathPattern;
import org.springframework.web.util.pattern.PathPatternParser;

/**
 * Match {@link Message}s based on the message destination pattern using a
 * {@link PathPattern}. There is also support for optionally matching on a specified
 * {@link SimpMessageType}.
 *
 * @author Pat McCusker
 * @since 6.5
 */
public final class PathPatternMessageMatcher implements MessageMatcher<Object> {

	public static final MessageMatcher<Object> NULL_DESTINATION_MATCHER = (message) -> getDestination(message) == null;

	private final PathPattern pattern;

	private final PathContainer.Options options;

	/**
	 * The {@link MessageMatcher} that determines if the type matches. If the type was
	 * null, this matcher will match every Message.
	 */
	private MessageMatcher<Object> messageTypeMatcher = ANY_MESSAGE;

	private PathPatternMessageMatcher(PathPattern pattern, PathContainer.Options options) {
		this.options = options;
		this.pattern = pattern;
	}

	/**
	 * Initialize this builder with the {@link PathPatternParser#defaultInstance} that is
	 * configured with the
	 * {@link org.springframework.http.server.PathContainer.Options#HTTP_PATH} separator
	 */
	public static Builder withDefaults() {
		return new Builder(PathPatternParser.defaultInstance);
	}

	/**
	 * Initialize this builder with the provided {@link PathPatternParser}
	 */
	public static Builder withPathPatternParser(PathPatternParser parser) {
		return new Builder(parser);
	}

	void setMessageTypeMatcher(MessageMatcher<Object> messageTypeMatcher) {
		this.messageTypeMatcher = messageTypeMatcher;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public boolean matches(Message<?> message) {
		return matcher(message).isMatch();
	}

	/**
	 * Extract the path variables from the {@link Message} destination if the path is a
	 * match, otherwise the {@link MatchResult#getVariables()} returns a
	 * {@link Collections#emptyMap()}
	 * @param message the message whose path variables to extract.
	 * @return a {@code MatchResult} of the path variables and values.
	 */
	@Override
	public MatchResult matcher(Message<?> message) {
		if (!this.messageTypeMatcher.matches(message)) {
			return MatchResult.notMatch();
		}

		String destination = getDestination(message);
		if (destination == null) {
			return MatchResult.notMatch();
		}

		PathContainer destinationPathContainer = PathContainer.parsePath(destination, this.options);
		PathPattern.PathMatchInfo pathMatchInfo = this.pattern.matchAndExtract(destinationPathContainer);

		return (pathMatchInfo != null) ? MatchResult.match(pathMatchInfo.getUriVariables()) : MatchResult.notMatch();
	}

	private static @Nullable String getDestination(Message<?> message) {
		return SimpMessageHeaderAccessor.getDestination(message.getHeaders());
	}

	/**
	 * A builder for specifying various elements of a message for the purpose of creating
	 * a {@link PathPatternMessageMatcher}.
	 */
	public static class Builder {

		private final PathPatternParser parser;

		Builder(PathPatternParser parser) {
			this.parser = parser;
		}

		/**
		 * Match messages having this destination pattern.
		 *
		 * <p>
		 * Path patterns always start with a slash and may contain placeholders. They can
		 * also be followed by {@code /**} to signify all URIs under a given path.
		 *
		 * <p>
		 * The following are valid patterns and their meaning
		 * <ul>
		 * <li>{@code /path} - match exactly and only `/path`</li>
		 * <li>{@code /path/**} - match `/path` and any of its descendants</li>
		 * <li>{@code /path/{value}/**} - match `/path/subdirectory` and any of its
		 * descendants, capturing the value of the subdirectory in
		 * {@link MessageAuthorizationContext#getVariables()}</li>
		 * </ul>
		 *
		 * <p>
		 * A more comprehensive list can be found at {@link PathPattern}.
		 *
		 * <p>
		 * A dot-based message pattern is also supported when configuring a
		 * {@link PathPatternParser} using
		 * {@link PathPatternMessageMatcher#withPathPatternParser}
		 * @param pattern the destination pattern to match
		 * @return the {@link PathPatternMessageMatcher.Builder} for more configuration
		 */
		public PathPatternMessageMatcher matcher(String pattern) {
			return matcher(null, pattern);
		}

		/**
		 * Match messages having this type and destination pattern.
		 *
		 * <p>
		 * When the message {@code type} is null, then the matcher does not consider the
		 * message type
		 *
		 * <p>
		 * Path patterns always start with a slash and may contain placeholders. They can
		 * also be followed by {@code /**} to signify all URIs under a given path.
		 *
		 * <p>
		 * The following are valid patterns and their meaning
		 * <ul>
		 * <li>{@code /path} - match exactly and only `/path`</li>
		 * <li>{@code /path/**} - match `/path` and any of its descendants</li>
		 * <li>{@code /path/{value}/**} - match `/path/subdirectory` and any of its
		 * descendants, capturing the value of the subdirectory in
		 * {@link MessageAuthorizationContext#getVariables()}</li>
		 * </ul>
		 *
		 * <p>
		 * A more comprehensive list can be found at {@link PathPattern}.
		 *
		 * <p>
		 * A dot-based message pattern is also supported when configuring a
		 * {@link PathPatternParser} using
		 * {@link PathPatternMessageMatcher#withPathPatternParser}
		 * @param type the message type to match
		 * @param pattern the destination pattern to match
		 * @return the {@link PathPatternMessageMatcher.Builder} for more configuration
		 */
		public PathPatternMessageMatcher matcher(@Nullable SimpMessageType type, String pattern) {
			Assert.notNull(pattern, "pattern must not be null");
			PathPattern pathPattern = this.parser.parse(pattern);
			PathPatternMessageMatcher matcher = new PathPatternMessageMatcher(pathPattern,
					this.parser.getPathOptions());
			if (type != null) {
				matcher.setMessageTypeMatcher(new SimpMessageTypeMatcher(type));
			}
			return matcher;
		}

	}

}
