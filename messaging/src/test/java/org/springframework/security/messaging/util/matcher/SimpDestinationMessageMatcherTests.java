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
	public void matchesDoesNotMatchNullDestination() {
		assertThat(matcher.matches(messageBuilder.build())).isFalse();
	}

	@Test
	public void matchesAllWithDestination() {
		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/1");

		assertThat(matcher.matches(messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesSpecificWithDestination() {
		matcher = new SimpDestinationMessageMatcher("/destination/1");

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/1");

		assertThat(matcher.matches(messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesFalseWithDestination() {
		matcher = new SimpDestinationMessageMatcher("/nomatch");

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/1");

		assertThat(matcher.matches(messageBuilder.build())).isFalse();
	}

	@Test
	public void matchesFalseMessageTypeNotDisconnectType() {
		matcher = SimpDestinationMessageMatcher.createMessageMatcher("/match", pathMatcher);

		messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.DISCONNECT);

		assertThat(matcher.matches(messageBuilder.build())).isFalse();
	}

	@Test
	public void matchesTrueMessageType() {
		matcher = SimpDestinationMessageMatcher.createMessageMatcher("/match", pathMatcher);

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE);

		assertThat(matcher.matches(messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesTrueSubscribeType() {
		matcher = SimpDestinationMessageMatcher.createSubscribeMatcher("/match", pathMatcher);

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.SUBSCRIBE);

		assertThat(matcher.matches(messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesNullMessageType() {
		matcher = new SimpDestinationMessageMatcher("/match");

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE);

		assertThat(matcher.matches(messageBuilder.build())).isTrue();
	}

	@Test
	public void extractPathVariablesFromDestination() {
		matcher = new SimpDestinationMessageMatcher("/topics/{topic}/**");

		messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/topics/someTopic/sub1");
		messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE);

		assertThat(matcher.extractPathVariables(messageBuilder.build()).get("topic")).isEqualTo("someTopic");
	}

	@Test
	public void extractedVariablesAreEmptyInNullDestination() {
		matcher = new SimpDestinationMessageMatcher("/topics/{topic}/**");
		assertThat(matcher.extractPathVariables(messageBuilder.build())).isEmpty();
	}

	@Test
	public void typeConstructorParameterIsTransmitted() {
		matcher = SimpDestinationMessageMatcher.createMessageMatcher("/match", pathMatcher);

		MessageMatcher<Object> expectedTypeMatcher = new SimpMessageTypeMatcher(SimpMessageType.MESSAGE);

		assertThat(matcher.getMessageTypeMatcher()).isEqualTo(expectedTypeMatcher);

	}

}
