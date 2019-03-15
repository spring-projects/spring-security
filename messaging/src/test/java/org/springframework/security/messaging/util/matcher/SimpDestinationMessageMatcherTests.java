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
package org.springframework.security.messaging.util.matcher;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.Before;
import org.junit.Test;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

public class SimpDestinationMessageMatcherTests {
	MessageBuilder<String> messageBuilder;

	SimpDestinationMessageMatcher matcher;

	PathMatcher pathMatcher;

	@Before
	public void setup() {
		messageBuilder = MessageBuilder.withPayload("M");
		matcher = new SimpDestinationMessageMatcher("/**");
		pathMatcher = new AntPathMatcher();
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorPatternNull() {
		new SimpDestinationMessageMatcher(null);
	}

	public void constructorOnlyPathNoError() {
		new SimpDestinationMessageMatcher("/path");
	}

	@Test
	public void matchesDoesNotMatchNullDestination() throws Exception {
		assertThat(matcher.matches(messageBuilder.build())).isFalse();
	}

	@Test
	public void matchesAllWithDestination() throws Exception {
		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER,
				"/destination/1");

		assertThat(matcher.matches(messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesSpecificWithDestination() throws Exception {
		matcher = new SimpDestinationMessageMatcher("/destination/1");

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER,
				"/destination/1");

		assertThat(matcher.matches(messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesFalseWithDestination() throws Exception {
		matcher = new SimpDestinationMessageMatcher("/nomatch");

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER,
				"/destination/1");

		assertThat(matcher.matches(messageBuilder.build())).isFalse();
	}

	@Test
	public void matchesFalseMessageTypeNotDisconnectType() throws Exception {
		matcher = SimpDestinationMessageMatcher.createMessageMatcher("/match",
				pathMatcher);

		messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER,
				SimpMessageType.DISCONNECT);

		assertThat(matcher.matches(messageBuilder.build())).isFalse();
	}

	@Test
	public void matchesTrueMessageType() throws Exception {
		matcher = SimpDestinationMessageMatcher.createMessageMatcher("/match",
				pathMatcher);

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER,
				SimpMessageType.MESSAGE);

		assertThat(matcher.matches(messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesTrueSubscribeType() throws Exception {
		matcher = SimpDestinationMessageMatcher.createSubscribeMatcher("/match",
				pathMatcher);

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER,
				SimpMessageType.SUBSCRIBE);

		assertThat(matcher.matches(messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesNullMessageType() throws Exception {
		matcher = new SimpDestinationMessageMatcher("/match");

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER,
				SimpMessageType.MESSAGE);

		assertThat(matcher.matches(messageBuilder.build())).isTrue();
	}

	@Test
	public void typeConstructorParameterIsTransmitted() throws Exception {
		matcher = SimpDestinationMessageMatcher.createMessageMatcher("/match",
				pathMatcher);

		MessageMatcher<Object> expectedTypeMatcher = new SimpMessageTypeMatcher(
				SimpMessageType.MESSAGE);

		assertThat(matcher.getMessageTypeMatcher()).isEqualTo(expectedTypeMatcher);

	}

}