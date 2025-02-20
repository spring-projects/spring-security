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
import java.util.Map;

import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.util.Assert;
import org.springframework.util.RouteMatcher;
import org.springframework.web.util.pattern.PathPatternParser;
import org.springframework.web.util.pattern.PathPatternRouteMatcher;

/**
 * Match {@link Message}s based on the message destination pattern, delegating the
 * matching to a {@link PathPatternRouteMatcher}. There is also support for optionally
 * matching on a specified {@link SimpMessageType}.
 *
 * @author Pat McCusker
 * @since 6.5
 */
public final class DestinationPathPatternMessageMatcher implements MessageMatcher<Object> {

	public static final MessageMatcher<Object> NULL_DESTINATION_MATCHER = (message) -> getDestination(message) == null;

	private static final PathPatternRouteMatcher SLASH_SEPARATED_ROUTE_MATCHER = new PathPatternRouteMatcher(
			PathPatternParser.defaultInstance);

	private static final PathPatternRouteMatcher DOT_SEPARATED_ROUTE_MATCHER = new PathPatternRouteMatcher();

	private final String patternToMatch;

	private final PathPatternRouteMatcher delegate;

	/**
	 * The {@link MessageMatcher} that determines if the type matches. If the type was
	 * null, this matcher will match every Message.
	 */
	private MessageMatcher<Object> messageTypeMatcher = ANY_MESSAGE;

	private DestinationPathPatternMessageMatcher(String pattern, PathPatternRouteMatcher matcher) {
		this.patternToMatch = pattern;
		this.delegate = matcher;
	}

	/**
	 * Initialize this builder with a {@link PathPatternRouteMatcher} configured with the
	 * {@link org.springframework.http.server.PathContainer.Options#HTTP_PATH} separator
	 */
	public static Builder withDefaults() {
		return new Builder(SLASH_SEPARATED_ROUTE_MATCHER);
	}

	/**
	 * Initialize this builder with a {@link PathPatternRouteMatcher} configured with the
	 * {@link org.springframework.http.server.PathContainer.Options#MESSAGE_ROUTE}
	 * separator
	 */
	public static Builder messageRoute() {
		return new Builder(DOT_SEPARATED_ROUTE_MATCHER);
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

		final String destination = getDestination(message);
		if (destination == null) {
			return false;
		}

		final RouteMatcher.Route destinationRoute = this.delegate.parseRoute(destination);
		return this.delegate.match(this.patternToMatch, destinationRoute);
	}

	/**
	 * Extract the path variables from the {@link Message} destination if the path is a
	 * match.
	 * @param message the message whose path variables to extract.
	 * @return a {@code Map} of the path variables and values.
	 * @throws IllegalStateException if the path does not match.
	 */
	public Map<String, String> extractPathVariables(Message<?> message) {
		final String destination = getDestination(message);
		if (destination == null) {
			return Collections.emptyMap();
		}

		final RouteMatcher.Route destinationRoute = this.delegate.parseRoute(destination);
		Map<String, String> pathMatchInfo = this.delegate.matchAndExtract(this.patternToMatch, destinationRoute);

		Assert.state(pathMatchInfo != null,
				"Pattern \"" + this.patternToMatch + "\" is not a match for \"" + destination + "\"");

		return pathMatchInfo;
	}

	private static String getDestination(Message<?> message) {
		return SimpMessageHeaderAccessor.getDestination(message.getHeaders());
	}

	public static class Builder {

		private final PathPatternRouteMatcher routeMatcher;

		private MessageMatcher<Object> messageTypeMatcher = ANY_MESSAGE;

		Builder(PathPatternRouteMatcher matcher) {
			this.routeMatcher = matcher;
		}

		public Builder messageType(SimpMessageType type) {
			Assert.notNull(type, "Type must not be null");
			this.messageTypeMatcher = new SimpMessageTypeMatcher(type);
			return this;
		}

		public DestinationPathPatternMessageMatcher matcher(String pattern) {
			Assert.notNull(pattern, "Pattern must not be null");
			DestinationPathPatternMessageMatcher matcher = new DestinationPathPatternMessageMatcher(pattern,
					this.routeMatcher);
			if (this.messageTypeMatcher != ANY_MESSAGE) {
				matcher.setMessageTypeMatcher(this.messageTypeMatcher);
			}
			return matcher;
		}

	}

}
