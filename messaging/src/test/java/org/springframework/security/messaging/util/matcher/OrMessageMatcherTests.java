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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.messaging.Message;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@RunWith(MockitoJUnitRunner.class)
public class OrMessageMatcherTests {

	@Mock
	private MessageMatcher<Object> delegate;

	@Mock
	private MessageMatcher<Object> delegate2;

	@Mock
	private Message<Object> message;

	private MessageMatcher<Object> matcher;

	@Test(expected = NullPointerException.class)
	public void constructorNullArray() {
		new OrMessageMatcher<>((MessageMatcher<Object>[]) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayContainsNull() {
		new OrMessageMatcher<>((MessageMatcher<Object>) null);
	}

	@SuppressWarnings("unchecked")
	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyArray() {
		new OrMessageMatcher<>(new MessageMatcher[0]);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullList() {
		new OrMessageMatcher<>((List<MessageMatcher<Object>>) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorListContainsNull() {
		new OrMessageMatcher<>(Arrays.asList((MessageMatcher<Object>) null));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyList() {
		new OrMessageMatcher<>(Collections.emptyList());
	}

	@Test
	public void matchesSingleTrue() {
		when(this.delegate.matches(this.message)).thenReturn(true);
		this.matcher = new OrMessageMatcher<>(this.delegate);

		assertThat(this.matcher.matches(this.message)).isTrue();
	}

	@Test
	public void matchesMultiTrue() {
		when(this.delegate.matches(this.message)).thenReturn(true);
		this.matcher = new OrMessageMatcher<>(this.delegate, this.delegate2);

		assertThat(this.matcher.matches(this.message)).isTrue();
	}

	@Test
	public void matchesSingleFalse() {
		when(this.delegate.matches(this.message)).thenReturn(false);
		this.matcher = new OrMessageMatcher<>(this.delegate);

		assertThat(this.matcher.matches(this.message)).isFalse();
	}

	@Test
	public void matchesMultiBothFalse() {
		when(this.delegate.matches(this.message)).thenReturn(false);
		when(this.delegate2.matches(this.message)).thenReturn(false);
		this.matcher = new OrMessageMatcher<>(this.delegate, this.delegate2);

		assertThat(this.matcher.matches(this.message)).isFalse();
	}

	@Test
	public void matchesMultiSingleFalse() {
		when(this.delegate.matches(this.message)).thenReturn(true);
		this.matcher = new OrMessageMatcher<>(this.delegate, this.delegate2);

		assertThat(this.matcher.matches(this.message)).isTrue();
	}

}
