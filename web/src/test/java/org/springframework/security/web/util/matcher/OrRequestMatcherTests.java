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
package org.springframework.security.web.util.matcher;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

/**
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class OrRequestMatcherTests {

	@Mock
	private RequestMatcher delegate;

	@Mock
	private RequestMatcher delegate2;

	@Mock
	private HttpServletRequest request;

	private RequestMatcher matcher;

	@Test(expected = NullPointerException.class)
	public void constructorNullArray() {
		new OrRequestMatcher((RequestMatcher[]) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorArrayContainsNull() {
		new OrRequestMatcher((RequestMatcher) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyArray() {
		new OrRequestMatcher(new RequestMatcher[0]);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullList() {
		new OrRequestMatcher((List<RequestMatcher>) null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorListContainsNull() {
		new OrRequestMatcher(Arrays.asList((RequestMatcher) null));
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyList() {
		new OrRequestMatcher(Collections.<RequestMatcher>emptyList());
	}

	@Test
	public void matchesSingleTrue() {
		when(delegate.matches(request)).thenReturn(true);
		matcher = new OrRequestMatcher(delegate);

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchesMultiTrue() {
		when(delegate.matches(request)).thenReturn(true);
		matcher = new OrRequestMatcher(delegate, delegate2);

		assertThat(matcher.matches(request)).isTrue();
	}

	@Test
	public void matchesSingleFalse() {
		when(delegate.matches(request)).thenReturn(false);
		matcher = new OrRequestMatcher(delegate);

		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void matchesMultiBothFalse() {
		when(delegate.matches(request)).thenReturn(false);
		when(delegate2.matches(request)).thenReturn(false);
		matcher = new OrRequestMatcher(delegate, delegate2);

		assertThat(matcher.matches(request)).isFalse();
	}

	@Test
	public void matchesMultiSingleFalse() {
		when(delegate.matches(request)).thenReturn(true);
		matcher = new OrRequestMatcher(delegate, delegate2);

		assertThat(matcher.matches(request)).isTrue();
	}

}
