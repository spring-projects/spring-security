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
import static org.mockito.Mockito.when;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.messaging.Message;

@RunWith(MockitoJUnitRunner.class)
public class AndMessageMatcherTests {

	@Mock
	private MessageMatcher<Object> delegate;

	@Mock
	private MessageMatcher<Object> delegate2;

	@Mock
	private Message<Object> message;

	private MessageMatcher<Object> matcher;

	@Test(expected = NullPointerException.class)
	public void constructorNullArray() {
		new AndMessageMatcher<>((MessageMatcher<Object>[]) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayContainsNull() {
		new AndMessageMatcher<>((MessageMatcher<Object>) null);
	}

	@SuppressWarnings("unchecked")
	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyArray() {
		new AndMessageMatcher<>((MessageMatcher<Object>[]) new MessageMatcher[0]);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullList() {
		new AndMessageMatcher<>((List<MessageMatcher<Object>>) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorListContainsNull() {
		new AndMessageMatcher<>(Arrays.asList((MessageMatcher<Object>) null));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyList() {
		new AndMessageMatcher<>(Collections.emptyList());
	}

	@Test
	public void matchesSingleTrue() {
		when(delegate.matches(message)).thenReturn(true);
		matcher = new AndMessageMatcher<>(delegate);

		assertThat(matcher.matches(message)).isTrue();
	}

	@Test
	public void matchesMultiTrue() {
		when(delegate.matches(message)).thenReturn(true);
		when(delegate2.matches(message)).thenReturn(true);
		matcher = new AndMessageMatcher<>(delegate, delegate2);

		assertThat(matcher.matches(message)).isTrue();
	}

	@Test
	public void matchesSingleFalse() {
		when(delegate.matches(message)).thenReturn(false);
		matcher = new AndMessageMatcher<>(delegate);

		assertThat(matcher.matches(message)).isFalse();
	}

	@Test
	public void matchesMultiBothFalse() {
		when(delegate.matches(message)).thenReturn(false);
		matcher = new AndMessageMatcher<>(delegate, delegate2);

		assertThat(matcher.matches(message)).isFalse();
	}

	@Test
	public void matchesMultiSingleFalse() {
		when(delegate.matches(message)).thenReturn(true);
		when(delegate2.matches(message)).thenReturn(false);
		matcher = new AndMessageMatcher<>(delegate, delegate2);

		assertThat(matcher.matches(message)).isFalse();
	}

}
