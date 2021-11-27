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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.messaging.Message;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

public class SimpMessageTypeMatcherTests {

	private SimpMessageTypeMatcher matcher;

	@BeforeEach
	public void setup() {
		this.matcher = new SimpMessageTypeMatcher(SimpMessageType.MESSAGE);
	}

	@Test
	public void constructorNullType() {
		assertThatIllegalArgumentException().isThrownBy(() -> new SimpMessageTypeMatcher(null));
	}

	@Test
	public void matchesMessageMessageTrue() {
		// @formatter:off
		Message<String> message = MessageBuilder.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE)
				.build();
		// @formatter:on
		assertThat(this.matcher.matches(message)).isTrue();
	}

	@Test
	public void matchesMessageConnectFalse() {
		// @formatter:off
		Message<String> message = MessageBuilder.withPayload("Hi")
				.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.CONNECT)
				.build();
		// @formatter:on
		assertThat(this.matcher.matches(message)).isFalse();
	}

	@Test
	public void matchesMessageNullFalse() {
		Message<String> message = MessageBuilder.withPayload("Hi").build();
		assertThat(this.matcher.matches(message)).isFalse();
	}

}
