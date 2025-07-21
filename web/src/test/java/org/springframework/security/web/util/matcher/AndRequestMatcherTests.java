/*
 * Copyright 2002-2023 the original author or authors.
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
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.web.util.matcher.RequestMatcher.MatchResult;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;
import static org.mockito.BDDMockito.given;
import static org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher.pathPattern;

/**
 * @author Rob Winch
 *
 */
@ExtendWith(MockitoExtension.class)
public class AndRequestMatcherTests {

	@Mock
	private RequestMatcher delegate;

	@Mock
	private RequestMatcher delegate2;

	@Mock
	private HttpServletRequest request;

	private RequestMatcher matcher;

	@Test
	public void constructorNullArray() {
		assertThatNullPointerException().isThrownBy(() -> new AndRequestMatcher((RequestMatcher[]) null));
	}

	@Test
	public void constructorListOfDoesNotThrowNullPointer() {
		new AndRequestMatcher(List.of(pathPattern("/test")));
	}

	@Test
	public void constructorArrayContainsNull() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AndRequestMatcher((RequestMatcher) null));
	}

	@Test
	public void constructorEmptyArray() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AndRequestMatcher(new RequestMatcher[0]));
	}

	@Test
	public void constructorNullList() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AndRequestMatcher((List<RequestMatcher>) null));
	}

	@Test
	public void constructorListContainsNull() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new AndRequestMatcher(Arrays.asList((RequestMatcher) null)));
	}

	@Test
	public void constructorEmptyList() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new AndRequestMatcher(Collections.<RequestMatcher>emptyList()));
	}

	@Test
	public void matchesSingleTrue() {
		given(this.delegate.matches(this.request)).willReturn(true);
		this.matcher = new AndRequestMatcher(this.delegate);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchesMultiTrue() {
		given(this.delegate.matches(this.request)).willReturn(true);
		given(this.delegate2.matches(this.request)).willReturn(true);
		this.matcher = new AndRequestMatcher(this.delegate, this.delegate2);
		assertThat(this.matcher.matches(this.request)).isTrue();
	}

	@Test
	public void matchesSingleFalse() {
		given(this.delegate.matches(this.request)).willReturn(false);
		this.matcher = new AndRequestMatcher(this.delegate);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void matchesMultiBothFalse() {
		given(this.delegate.matches(this.request)).willReturn(false);
		this.matcher = new AndRequestMatcher(this.delegate, this.delegate2);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void matchesMultiSingleFalse() {
		given(this.delegate.matches(this.request)).willReturn(true);
		given(this.delegate2.matches(this.request)).willReturn(false);
		this.matcher = new AndRequestMatcher(this.delegate, this.delegate2);
		assertThat(this.matcher.matches(this.request)).isFalse();
	}

	@Test
	public void matcherWhenMatchersHavePlaceholdersThenPropagatesMatches() {
		this.matcher = new AndRequestMatcher(this.delegate, this.delegate2);

		given(this.delegate.matcher(this.request)).willReturn(MatchResult.match(Map.of("param", "value")));
		given(this.delegate2.matcher(this.request)).willReturn(MatchResult.match(Map.of("param", "othervalue")));
		MatchResult result = this.matcher.matcher(this.request);
		assertThat(result.getVariables()).containsExactlyEntriesOf(Map.of("param", "othervalue"));

		given(this.delegate.matcher(this.request)).willReturn(MatchResult.match());
		given(this.delegate2.matcher(this.request)).willReturn(MatchResult.match(Map.of("param", "value")));
		result = this.matcher.matcher(this.request);
		assertThat(result.getVariables()).containsExactlyEntriesOf(Map.of("param", "value"));

		given(this.delegate.matcher(this.request)).willReturn(MatchResult.match(Map.of("param", "value")));
		given(this.delegate2.matcher(this.request)).willReturn(MatchResult.notMatch());
		result = this.matcher.matcher(this.request);
		assertThat(result.getVariables()).isEmpty();

		given(this.delegate.matcher(this.request)).willReturn(MatchResult.match(Map.of("otherparam", "value")));
		given(this.delegate2.matcher(this.request)).willReturn(MatchResult.match(Map.of("param", "value")));
		result = this.matcher.matcher(this.request);
		assertThat(result.getVariables())
			.containsExactlyInAnyOrderEntriesOf(Map.of("otherparam", "value", "param", "value"));
	}

}
