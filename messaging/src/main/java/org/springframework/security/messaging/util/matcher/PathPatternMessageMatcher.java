/*
 * Copyright 2002-2025 the original author or authors.
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

import org.springframework.http.server.PathContainer;
import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
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

	private final PathPatternParser parser;

	/**
	 * The {@link MessageMatcher} that determines if the type matches. If the type was
	 * null, this matcher will match every Message.
	 */
	private MessageMatcher<Object> messageTypeMatcher = ANY_MESSAGE;

	private PathPatternMessageMatcher(PathPattern pattern, PathPatternParser parser) {
		this.parser = parser;
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
		if (!this.messageTypeMatcher.matches(message)) {
			return false;
		}

		String destination = getDestination(message);
		if (destination == null) {
			return false;
		}

		PathContainer destinationPathContainer = PathContainer.parsePath(destination, this.parser.getPathOptions());
		return this.pattern.matches(destinationPathContainer);
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

		PathContainer destinationPathContainer = PathContainer.parsePath(destination, this.parser.getPathOptions());
		PathPattern.PathMatchInfo pathMatchInfo = this.pattern.matchAndExtract(destinationPathContainer);

		return (pathMatchInfo != null) ? MatchResult.match(pathMatchInfo.getUriVariables()) : MatchResult.notMatch();
	}

	private static String getDestination(Message<?> message) {
		return SimpMessageHeaderAccessor.getDestination(message.getHeaders());
	}

	public static class Builder {

		private final PathPatternParser parser;

		private MessageMatcher<Object> messageTypeMatcher = ANY_MESSAGE;

		Builder(PathPatternParser parser) {
			this.parser = parser;
		}

		public PathPatternMessageMatcher matcher(String pattern) {
			Assert.notNull(pattern, "Pattern must not be null");
			PathPattern pathPattern = this.parser.parse(pattern);
			PathPatternMessageMatcher matcher = new PathPatternMessageMatcher(pathPattern, this.parser);
			if (this.messageTypeMatcher != ANY_MESSAGE) {
				matcher.setMessageTypeMatcher(this.messageTypeMatcher);
			}
			return matcher;
		}

		public PathPatternMessageMatcher matcher(String pattern, SimpMessageType type) {
			Assert.notNull(type, "Type must not be null");
			this.messageTypeMatcher = new SimpMessageTypeMatcher(type);

			return matcher(pattern);
		}

	}

}
