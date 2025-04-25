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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.server.PathContainer;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.simp.SimpMessageType;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.web.util.pattern.PathPatternParser;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

public class PathPatternMessageMatcherTests {

	MessageBuilder<String> messageBuilder;

	PathPatternMessageMatcher matcher;

	@BeforeEach
	void setUp() {
		this.messageBuilder = MessageBuilder.withPayload("M");
		this.matcher = PathPatternMessageMatcher.withDefaults().matcher("/**");
	}

	@Test
	void constructorPatternNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> PathPatternMessageMatcher.withDefaults().matcher(null));
	}

	@Test
	void matchesDoesNotMatchNullDestination() {
		assertThat(this.matcher.matches(this.messageBuilder.build())).isFalse();
	}

	@Test
	void matchesTrueWithSpecificDestinationPattern() {
		this.matcher = PathPatternMessageMatcher.withDefaults().matcher("/destination/1");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/1");
		assertThat(this.matcher.matches(this.messageBuilder.build())).isTrue();
	}

	@Test
	void matchesFalseWithDifferentDestination() {
		this.matcher = PathPatternMessageMatcher.withDefaults().matcher("/nomatch");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/1");
		assertThat(this.matcher.matches(this.messageBuilder.build())).isFalse();
	}

	@Test
	void matchesTrueWithDotSeparator() {
		this.matcher = PathPatternMessageMatcher.withPathPatternParser(dotSeparatedPathParser())
			.matcher("destination.1");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "destination.1");
		assertThat(this.matcher.matches(this.messageBuilder.build())).isTrue();
	}

	@Test
	void matchesFalseWithDotSeparatorAndAdditionalWildcardPathSegment() {
		this.matcher = PathPatternMessageMatcher.withPathPatternParser(dotSeparatedPathParser())
			.matcher("/destination/a.*");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/a.b");
		assertThat(this.matcher.matches(this.messageBuilder.build())).isTrue();
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/a.b.c");
		assertThat(this.matcher.matches(this.messageBuilder.build())).isFalse();
	}

	@Test
	void matchesFalseWithDifferentMessageType() {
		this.matcher = PathPatternMessageMatcher.withDefaults().matcher(SimpMessageType.MESSAGE, "/match");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.DISCONNECT);
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");

		assertThat(this.matcher.matches(this.messageBuilder.build())).isFalse();
	}

	@Test
	void matchesTrueMessageType() {
		this.matcher = PathPatternMessageMatcher.withDefaults().matcher(SimpMessageType.MESSAGE, "/match");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE);
		assertThat(this.matcher.matches(this.messageBuilder.build())).isTrue();
	}

	@Test
	void matchesTrueSubscribeType() {
		this.matcher = PathPatternMessageMatcher.withDefaults().matcher(SimpMessageType.SUBSCRIBE, "/match");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/match");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.SUBSCRIBE);
		assertThat(this.matcher.matches(this.messageBuilder.build())).isTrue();
	}

	@Test
	void extractPathVariablesFromDestination() {
		this.matcher = PathPatternMessageMatcher.withDefaults().matcher("/topics/{topic}/**");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/topics/someTopic/sub1");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE);

		MessageMatcher.MatchResult matchResult = this.matcher.matcher(this.messageBuilder.build());
		assertThat(matchResult.isMatch()).isTrue();
		assertThat(matchResult.getVariables()).containsEntry("topic", "someTopic");
	}

	@Test
	void extractPathVariablesFromMessageDestinationPath() {
		this.matcher = PathPatternMessageMatcher.withPathPatternParser(dotSeparatedPathParser())
			.matcher("destination.{destinationNum}");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "destination.1");
		MessageMatcher.MatchResult matchResult = this.matcher.matcher(this.messageBuilder.build());
		assertThat(matchResult.getVariables()).containsEntry("destinationNum", "1");
	}

	@Test
	void extractPathVariables_isEmptyWithNullDestination() {
		this.matcher = PathPatternMessageMatcher.withDefaults().matcher("/topics/{topic}/**");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.MESSAGE_TYPE_HEADER, SimpMessageType.MESSAGE);

		MessageMatcher.MatchResult matchResult = this.matcher.matcher(this.messageBuilder.build());
		assertThat(matchResult.isMatch()).isFalse();
		assertThat(matchResult.getVariables()).isEmpty();
	}

	@Test
	void getUriVariablesIsEmpty_onExtractPathVariables_whenNoMatch() {
		this.matcher = PathPatternMessageMatcher.withDefaults().matcher("/nomatch");
		this.messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER, "/destination/1");
		MessageMatcher.MatchResult matchResult = this.matcher.matcher(this.messageBuilder.build());
		assertThat(matchResult.isMatch()).isFalse();
		assertThat(matchResult.getVariables()).isEmpty();
	}

	private static PathPatternParser dotSeparatedPathParser() {
		PathPatternParser parser = new PathPatternParser();
		parser.setPathOptions(PathContainer.Options.MESSAGE_ROUTE);
		return parser;
	}

}
