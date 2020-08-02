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

import org.junit.Before;
import org.junit.Test;

import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.util.AntPathMatcher;
import org.springframework.util.PathMatcher;

import static org.assertj.core.api.Assertions.assertThat;

public class SimpDestinationMessageMatcherTests {

	MessageBuilder<String> messageBuilder;

	SimpDestinationMessageMatcher matcher;

	PathMatcher pathMatcher;

	@Before
	public void setup() {
		this.messageBuilder = MessageBuilder.withPayload("M");
		this.matcher = new SimpDestinationMessageMatcher("/**");
		this.pathMatcher = new AntPathMatcher();
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
		assertThat(this.matcher.matches(this.messageBuilder.build())).isFalse();
	}

	@Test
	public void matchesAllWithDestination() {
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/1");
		assertThat(this.matcher.matches(this.messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesSpecificWithDestination() {
		this.matcher = new SimpDestinationMessageMatcher("/destination/1");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/1");
		assertThat(this.matcher.matches(this.messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesFalseWithDestination() {
		this.matcher = new SimpDestinationMessageMatcher("/nomatch");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/1");
		assertThat(this.matcher.matches(this.messageBuilder.build())).isFalse();
	}

	@Test
	public void matchesFalseMessageTypeNotDisconnectType() {
		this.matcher = SimpDestinationMessageMatcher.createMessageMatcher("/match", this.pathMatcher);
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.DISCONNECT);
		assertThat(this.matcher.matches(this.messageBuilder.build())).isFalse();
	}

	@Test
	public void matchesTrueMessageType() {
		this.matcher = SimpDestinationMessageMatcher.createMessageMatcher("/match", this.pathMatcher);
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE);
		assertThat(this.matcher.matches(this.messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesTrueSubscribeType() {
		this.matcher = SimpDestinationMessageMatcher.createSubscribeMatcher("/match", this.pathMatcher);
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.SUBSCRIBE);
		assertThat(this.matcher.matches(this.messageBuilder.build())).isTrue();
	}

	@Test
	public void matchesNullMessageType() {
		this.matcher = new SimpDestinationMessageMatcher("/match");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE);
		assertThat(this.matcher.matches(this.messageBuilder.build())).isTrue();
	}

	@Test
	public void extractPathVariablesFromDestination() {
		this.matcher = new SimpDestinationMessageMatcher("/topics/{topic}/**");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/topics/someTopic/sub1");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE);
		assertThat(this.matcher.extractPathVariables(this.messageBuilder.build()).get("topic")).isEqualTo("someTopic");
	}

	@Test
	public void extractedVariablesAreEmptyInNullDestination() {
		this.matcher = new SimpDestinationMessageMatcher("/topics/{topic}/**");
		assertThat(this.matcher.extractPathVariables(this.messageBuilder.build())).isEmpty();
	}

	@Test
	public void typeConstructorParameterIsTransmitted() {
		this.matcher = SimpDestinationMessageMatcher.createMessageMatcher("/match", this.pathMatcher);
		MessageMatcher<Object> expectedTypeMatcher = new SimpMessageTypeMatcher(SimpMessageType.MESSAGE);
		assertThat(this.matcher.getMessageTypeMatcher()).isEqualTo(expectedTypeMatcher);
	}

}
