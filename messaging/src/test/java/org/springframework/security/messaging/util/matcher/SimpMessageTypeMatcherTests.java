/*
 * Copyright 2002-2013 the original author or authors.
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

import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;

import static org.assertj.core.api.Assertions.assertThat;

public class SimpMessageTypeMatcherTests {

	private SimpMessageTypeMatcher matcher;

	@Before
	public void setup() {
		this.matcher = new SimpMessageTypeMatcher(SimpMessageType.MESSAGE);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullType() {
		new SimpMessageTypeMatcher(null);
	}

	@Test
	public void matchesMessageMessageTrue() {
		Message<String> message = MessageBuilder.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE).build();

		assertThat(this.matcher.matches(message)).isTrue();
	}

	@Test
	public void matchesMessageConnectFalse() {
		Message<String> message = MessageBuilder.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.CONNECT).build();

		assertThat(this.matcher.matches(message)).isFalse();
	}

	@Test
	public void matchesMessageNullFalse() {
		Message<String> message = MessageBuilder.withPayload("Hi").build();

		assertThat(this.matcher.matches(message)).isFalse();
	}

}
