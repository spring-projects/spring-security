/*
 * Copyright 2002-2019 the original author or authors.
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
import org.springframework.util.AntPathMatcher;
import org.springframework.util.Assert;
import org.springframework.util.PathMatcher;

/**
 * <p>
 * MessageMatcher which compares a pre-defined pattern against the destination of a
 * {@link Message}. There is also support for optionally matching on a specified
 * {@link SimpMessageType}.
 * </p>
 *
 * @author Rob Winch
 * @since 4.0
 */
public final class SimpDestinationMessageMatcher implements MessageMatcher<Object> {

	public static final MessageMatcher<Object> NULL_DESTINATION_MATCHER = message -> {
		String destination = SimpMessageHeaderAccessor.getDestination(message.getHeaders());
		return destination == null;
	};

	private final PathMatcher matcher;

	/**
	 * The {@link MessageMatcher} that determines if the type matches. If the type was
	 * null, this matcher will match every Message.
	 */
	private final MessageMatcher<Object> messageTypeMatcher;

	private final String pattern;

	/**
	 * <p>
	 * Creates a new instance with the specified pattern, null {@link SimpMessageType}
	 * (matches any type), and a {@link AntPathMatcher} created from the default
	 * constructor.
	 *
	 * <p>
	 * The mapping matches destinations despite the using the following rules:
	 *
	 * <ul>
	 * <li>? matches one character</li>
	 * <li>* matches zero or more characters</li>
	 * <li>** matches zero or more 'directories' in a path</li>
	 * </ul>
	 *
	 * <p>
	 * Some examples:
	 *
	 * <ul>
	 * <li>{@code com/t?st.jsp} - matches {@code com/test} but also {@code com/tast} or
	 * {@code com/txst}</li>
	 * <li>{@code com/*suffix} - matches all files ending in {@code suffix} in the
	 * {@code com} directory</li>
	 * <li>{@code com/&#42;&#42;/test} - matches all destinations ending with {@code test}
	 * underneath the {@code com} path</li>
	 * </ul>
	 * @param pattern the pattern to use
	 */
	public SimpDestinationMessageMatcher(String pattern) {
		this(pattern, new AntPathMatcher());
	}

	/**
	 * <p>
	 * Creates a new instance with the specified pattern and {@link PathMatcher}.
	 * @param pattern the pattern to use
	 * @param pathMatcher the {@link PathMatcher} to use.
	 */
	public SimpDestinationMessageMatcher(String pattern, PathMatcher pathMatcher) {
		this(pattern, null, pathMatcher);
	}

	/**
	 * <p>
	 * Creates a new instance with the specified pattern, {@link SimpMessageType}, and
	 * {@link PathMatcher}.
	 * @param pattern the pattern to use
	 * @param type the {@link SimpMessageType} to match on or null if any
	 * {@link SimpMessageType} should be matched.
	 * @param pathMatcher the {@link PathMatcher} to use.
	 */
	private SimpDestinationMessageMatcher(String pattern, SimpMessageType type, PathMatcher pathMatcher) {
		Assert.notNull(pattern, "pattern cannot be null");
		Assert.notNull(pathMatcher, "pathMatcher cannot be null");
		if (!isTypeWithDestination(type)) {
			throw new IllegalArgumentException(
					"SimpMessageType " + type + " does not contain a destination and so cannot be matched on.");
		}

		this.matcher = pathMatcher;
		this.messageTypeMatcher = type == null ? ANY_MESSAGE : new SimpMessageTypeMatcher(type);
		this.pattern = pattern;
	}

	@Override
	public boolean matches(Message<?> message) {
		if (!this.messageTypeMatcher.matches(message)) {
			return false;
		}

		String destination = SimpMessageHeaderAccessor.getDestination(message.getHeaders());
		return destination != null && this.matcher.match(this.pattern, destination);
	}

	public Map<String, String> extractPathVariables(Message<?> message) {
		final String destination = SimpMessageHeaderAccessor.getDestination(message.getHeaders());
		return destination != null ? this.matcher.extractUriTemplateVariables(this.pattern, destination)
				: Collections.emptyMap();
	}

	public MessageMatcher<Object> getMessageTypeMatcher() {
		return this.messageTypeMatcher;
	}

	@Override
	public String toString() {
		return "SimpDestinationMessageMatcher [matcher=" + this.matcher + ", messageTypeMatcher="
				+ this.messageTypeMatcher + ", pattern=" + this.pattern + "]";
	}

	private boolean isTypeWithDestination(SimpMessageType type) {
		if (type == null) {
			return true;
		}
		return SimpMessageType.MESSAGE.equals(type) || SimpMessageType.SUBSCRIBE.equals(type);
	}

	/**
	 * <p>
	 * Creates a new instance with the specified pattern,
	 * {@code SimpMessageType.SUBSCRIBE}, and {@link PathMatcher}.
	 * @param pattern the pattern to use
	 * @param matcher the {@link PathMatcher} to use.
	 */
	public static SimpDestinationMessageMatcher createSubscribeMatcher(String pattern, PathMatcher matcher) {
		return new SimpDestinationMessageMatcher(pattern, SimpMessageType.SUBSCRIBE, matcher);
	}

	/**
	 * <p>
	 * Creates a new instance with the specified pattern, {@code SimpMessageType.MESSAGE},
	 * and {@link PathMatcher}.
	 * @param pattern the pattern to use
	 * @param matcher the {@link PathMatcher} to use.
	 */
	public static SimpDestinationMessageMatcher createMessageMatcher(String pattern, PathMatcher matcher) {
		return new SimpDestinationMessageMatcher(pattern, SimpMessageType.MESSAGE, matcher);
	}

}
