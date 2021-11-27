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

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.messaging.Message;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.BDDMockito.given;

@ExtendWith(MockitoExtension.class)
public class OrMessageMatcherTests {

	@Mock
	private MessageMatcher<Object> delegate;

	@Mock
	private MessageMatcher<Object> delegate2;

	@Mock
	private Message<Object> message;

	private MessageMatcher<Object> matcher;

	@Test
	public void constructorNullArray() {
		assertThatNullPointerException().isThrownBy(() -> new OrMessageMatcher<>((MessageMatcher<Object>[]) null));
	}

	@Test
	public void constructorArrayContainsNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OrMessageMatcher<>((MessageMatcher<Object>) null));
	}

	@Test
	@SuppressWarnings("unchecked")
	public void constructorEmptyArray() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OrMessageMatcher<>(new MessageMatcher[0]));
	}

	@Test
	public void constructorNullList() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OrMessageMatcher<>((List<MessageMatcher<Object>>) null));
	}

	@Test
	public void constructorListContainsNull() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new OrMessageMatcher<>(Arrays.asList((MessageMatcher<Object>) null)));
	}

	@Test
	public void constructorEmptyList() {
		assertThatIllegalArgumentException().isThrownBy(() -> new OrMessageMatcher<>(Collections.emptyList()));
	}

	@Test
	public void matchesSingleTrue() {
		given(this.delegate.matches(this.message)).willReturn(true);
		this.matcher = new OrMessageMatcher<>(this.delegate);
		assertThat(this.matcher.matches(this.message)).isTrue();
	}

	@Test
	public void matchesMultiTrue() {
		given(this.delegate.matches(this.message)).willReturn(true);
		this.matcher = new OrMessageMatcher<>(this.delegate, this.delegate2);
		assertThat(this.matcher.matches(this.message)).isTrue();
	}

	@Test
	public void matchesSingleFalse() {
		given(this.delegate.matches(this.message)).willReturn(false);
		this.matcher = new OrMessageMatcher<>(this.delegate);
		assertThat(this.matcher.matches(this.message)).isFalse();
	}

	@Test
	public void matchesMultiBothFalse() {
		given(this.delegate.matches(this.message)).willReturn(false);
		given(this.delegate2.matches(this.message)).willReturn(false);
		this.matcher = new OrMessageMatcher<>(this.delegate, this.delegate2);
		assertThat(this.matcher.matches(this.message)).isFalse();
	}

	@Test
	public void matchesMultiSingleFalse() {
		given(this.delegate.matches(this.message)).willReturn(true);
		this.matcher = new OrMessageMatcher<>(this.delegate, this.delegate2);
		assertThat(this.matcher.matches(this.message)).isTrue();
	}

}
