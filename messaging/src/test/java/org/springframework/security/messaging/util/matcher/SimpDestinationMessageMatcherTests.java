/*
 * Copyright 2002-2014 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.messaging.util.matcher;

import org.junit.Before;
import org.junit.Test;
import org.springframework.messaging.simp.SimpMessageHeaderAccessor;
import org.springframework.messaging.support.MessageBuilder;

import static org.fest.assertions.Assertions.assertThat;


public class SimpDestinationMessageMatcherTests {
    MessageBuilder<String> messageBuilder;

    SimpDestinationMessageMatcher matcher;

    @Before
    public void setup() {
        messageBuilder = MessageBuilder.withPayload("M");
        matcher = new SimpDestinationMessageMatcher("/**");
    }

    @Test(expected = IllegalArgumentException.class)
    public void constructorPatternNull() {
        new SimpDestinationMessageMatcher(null);
    }

    @Test
    public void matchesDoesNotMatchNullDestination() throws Exception {
        assertThat(matcher.matches(messageBuilder.build())).isFalse();
    }

    @Test
    public void matchesAllWithDestination() throws Exception {
        messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER,"/destination/1");

        assertThat(matcher.matches(messageBuilder.build())).isTrue();
    }

    @Test
    public void matchesSpecificWithDestination() throws Exception {
        matcher = new SimpDestinationMessageMatcher("/destination/1");

        messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER,"/destination/1");

        assertThat(matcher.matches(messageBuilder.build())).isTrue();
    }

    @Test
    public void matchesFalseWithDestination() throws Exception {
        matcher = new SimpDestinationMessageMatcher("/nomatch");

        messageBuilder.setHeader(SimpMessageHeaderAccessor.DESTINATION_HEADER,"/destination/1");

        assertThat(matcher.matches(messageBuilder.build())).isFalse();
    }
}