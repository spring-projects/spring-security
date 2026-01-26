/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.authentication;

import java.io.IOException;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcherEntry;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Test class for {@link DelegatingAuthenticationEntryPoint}
 *
 * @author Mike Wiesner
 * @since 3.0.2
 * @version $Id:$
 */
public class DelegatingAuthenticationEntryPointTests {

	private DelegatingAuthenticationEntryPoint daep;

	private LinkedHashMap<RequestMatcher, AuthenticationEntryPoint> entryPoints;

	private AuthenticationEntryPoint defaultEntryPoint;

	private HttpServletRequest request = new MockHttpServletRequest();

	@BeforeEach
	public void before() {
		this.defaultEntryPoint = mock(AuthenticationEntryPoint.class);
		this.entryPoints = new LinkedHashMap<>();
	}

	@Test
	@SuppressWarnings("removal")
	public void testDefaultEntryPoint() throws Exception {
		AuthenticationEntryPoint firstAEP = mock(AuthenticationEntryPoint.class);
		RequestMatcher firstRM = mock(RequestMatcher.class);
		given(firstRM.matches(this.request)).willReturn(false);
		this.entryPoints.put(firstRM, firstAEP);
		this.daep = new DelegatingAuthenticationEntryPoint(this.entryPoints);
		this.daep.setDefaultEntryPoint(this.defaultEntryPoint);
		this.daep.commence(this.request, null, null);
		verify(this.defaultEntryPoint).commence(this.request, null, null);
		verify(firstAEP, never()).commence(this.request, null, null);
	}

	@Test
	@SuppressWarnings("removal")
	public void testFirstEntryPoint() throws Exception {
		AuthenticationEntryPoint firstAEP = mock(AuthenticationEntryPoint.class);
		RequestMatcher firstRM = mock(RequestMatcher.class);
		AuthenticationEntryPoint secondAEP = mock(AuthenticationEntryPoint.class);
		RequestMatcher secondRM = mock(RequestMatcher.class);
		given(firstRM.matches(this.request)).willReturn(true);
		this.entryPoints.put(firstRM, firstAEP);
		this.entryPoints.put(secondRM, secondAEP);
		this.daep = new DelegatingAuthenticationEntryPoint(this.entryPoints);
		this.daep.setDefaultEntryPoint(this.defaultEntryPoint);
		this.daep.commence(this.request, null, null);
		verify(firstAEP).commence(this.request, null, null);
		verify(secondAEP, never()).commence(this.request, null, null);
		verify(this.defaultEntryPoint, never()).commence(this.request, null, null);
		verify(secondRM, never()).matches(this.request);
	}

	@Test
	@SuppressWarnings("removal")
	public void testSecondEntryPoint() throws Exception {
		AuthenticationEntryPoint firstAEP = mock(AuthenticationEntryPoint.class);
		RequestMatcher firstRM = mock(RequestMatcher.class);
		AuthenticationEntryPoint secondAEP = mock(AuthenticationEntryPoint.class);
		RequestMatcher secondRM = mock(RequestMatcher.class);
		given(firstRM.matches(this.request)).willReturn(false);
		given(secondRM.matches(this.request)).willReturn(true);
		this.entryPoints.put(firstRM, firstAEP);
		this.entryPoints.put(secondRM, secondAEP);
		this.daep = new DelegatingAuthenticationEntryPoint(this.entryPoints);
		this.daep.setDefaultEntryPoint(this.defaultEntryPoint);
		this.daep.commence(this.request, null, null);
		verify(secondAEP).commence(this.request, null, null);
		verify(firstAEP, never()).commence(this.request, null, null);
		verify(this.defaultEntryPoint, never()).commence(this.request, null, null);
	}

	@Test
	@SuppressWarnings("removal")
	public void constructorAepListWhenNullEntryPoints() {
		List<RequestMatcherEntry<AuthenticationEntryPoint>> entryPoints = null;
		assertThatIllegalArgumentException().isThrownBy(
				() -> new DelegatingAuthenticationEntryPoint(mock(AuthenticationEntryPoint.class), entryPoints));
	}

	@Test
	@SuppressWarnings("removal")
	public void constructorAepListWhenEmptyEntryPoints() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new DelegatingAuthenticationEntryPoint(mock(AuthenticationEntryPoint.class),
					Collections.emptyList()));
	}

	@Test
	@SuppressWarnings("removal")
	public void constructorAepListWhenNullDefaultEntryPoint() {
		AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);
		RequestMatcher matcher = mock(RequestMatcher.class);
		List<RequestMatcherEntry<AuthenticationEntryPoint>> entryPoints = List
			.of(new RequestMatcherEntry<>(matcher, entryPoint));
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new DelegatingAuthenticationEntryPoint(null, entryPoints));
	}

	@Test
	@SuppressWarnings("removal")
	public void constructorAepVargsWhenNullEntryPoints() {
		RequestMatcherEntry<AuthenticationEntryPoint>[] entryPoints = null;
		assertThatIllegalArgumentException().isThrownBy(
				() -> new DelegatingAuthenticationEntryPoint(mock(AuthenticationEntryPoint.class), entryPoints));
	}

	@Test
	@SuppressWarnings("removal")
	public void constructorAepVargsWhenEmptyEntryPoints() {
		RequestMatcherEntry<AuthenticationEntryPoint>[] entryPoints = new RequestMatcherEntry[0];
		assertThatIllegalArgumentException().isThrownBy(
				() -> new DelegatingAuthenticationEntryPoint(mock(AuthenticationEntryPoint.class), entryPoints));
	}

	@Test
	@SuppressWarnings("removal")
	public void constructorAepVargsWhenNullDefaultEntryPoint() {
		AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);
		RequestMatcher matcher = mock(RequestMatcher.class);
		RequestMatcherEntry<AuthenticationEntryPoint>[] entryPoints = new RequestMatcherEntry[] {
				new RequestMatcherEntry<>(matcher, entryPoint) };
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new DelegatingAuthenticationEntryPoint(null, entryPoints));
	}

	@Test
	@SuppressWarnings("removal")
	public void commenceWhenNoMatchThenDefaultEntryPoint() throws Exception {
		AuthenticationEntryPoint firstAEP = mock(AuthenticationEntryPoint.class);
		RequestMatcher firstRM = mock(RequestMatcher.class);
		given(firstRM.matches(this.request)).willReturn(false);
		RequestMatcherEntry<AuthenticationEntryPoint> entry = new RequestMatcherEntry<>(firstRM, firstAEP);
		this.daep = new DelegatingAuthenticationEntryPoint(this.defaultEntryPoint, entry);
		this.daep.commence(this.request, null, null);
		verify(this.defaultEntryPoint).commence(this.request, null, null);
		verify(firstAEP, never()).commence(this.request, null, null);
	}

	@Test
	@SuppressWarnings("removal")
	public void commenceWhenMatchFirstEntryPointThenOthersNotInvoked() throws Exception {
		AuthenticationEntryPoint firstAEP = mock(AuthenticationEntryPoint.class);
		RequestMatcher firstRM = mock(RequestMatcher.class);
		given(firstRM.matches(this.request)).willReturn(true);
		RequestMatcherEntry<AuthenticationEntryPoint> firstEntry = new RequestMatcherEntry<>(firstRM, firstAEP);
		AuthenticationEntryPoint secondAEP = mock(AuthenticationEntryPoint.class);
		RequestMatcher secondRM = mock(RequestMatcher.class);
		given(secondRM.matches(this.request)).willReturn(false);
		RequestMatcherEntry<AuthenticationEntryPoint> secondEntry = new RequestMatcherEntry<>(firstRM, firstAEP);
		this.daep = new DelegatingAuthenticationEntryPoint(this.defaultEntryPoint, firstEntry, secondEntry);
		this.daep.commence(this.request, null, null);
		verify(firstAEP).commence(this.request, null, null);
		verify(secondAEP, never()).commence(this.request, null, null);
		verify(this.defaultEntryPoint, never()).commence(this.request, null, null);
		verify(secondRM, never()).matches(this.request);
	}

	@Test
	@SuppressWarnings("removal")
	public void commenceWhenSecondMatchesThenDefaultNotInvoked() throws Exception {
		AuthenticationEntryPoint firstAEP = mock(AuthenticationEntryPoint.class);
		RequestMatcher firstRM = mock(RequestMatcher.class);
		given(firstRM.matches(this.request)).willReturn(false);
		RequestMatcherEntry<AuthenticationEntryPoint> firstEntry = new RequestMatcherEntry<>(firstRM, firstAEP);
		AuthenticationEntryPoint secondAEP = mock(AuthenticationEntryPoint.class);
		RequestMatcher secondRM = mock(RequestMatcher.class);
		given(secondRM.matches(this.request)).willReturn(true);
		RequestMatcherEntry<AuthenticationEntryPoint> secondEntry = new RequestMatcherEntry<>(secondRM, secondAEP);
		this.daep = new DelegatingAuthenticationEntryPoint(this.defaultEntryPoint, firstEntry, secondEntry);
		this.daep.commence(this.request, null, null);
		verify(secondAEP).commence(this.request, null, null);
		verify(firstAEP, never()).commence(this.request, null, null);
		verify(this.defaultEntryPoint, never()).commence(this.request, null, null);
	}

	@Test
	void builderWhenDefaultNullAndSingleEntryPointThenReturnsSingle() {
		AuthenticationEntryPoint entryPoint = mock(AuthenticationEntryPoint.class);

		AuthenticationEntryPoint result = DelegatingAuthenticationEntryPoint.builder()
			.addEntryPointFor(entryPoint, mock(RequestMatcher.class))
			.build();

		assertThat(result).isEqualTo(entryPoint);
	}

	@Test
	@SuppressWarnings("removal")
	void builderWhenDefaultNullThenFirstIsDefault() throws ServletException, IOException {
		AuthenticationEntryPoint firstEntryPoint = mock(AuthenticationEntryPoint.class);
		AuthenticationEntryPoint secondEntryPoint = mock(AuthenticationEntryPoint.class);
		RequestMatcher neverMatch = mock(RequestMatcher.class);
		given(neverMatch.matches(this.request)).willReturn(false);
		AuthenticationEntryPoint result = DelegatingAuthenticationEntryPoint.builder()
			.addEntryPointFor(firstEntryPoint, neverMatch)
			.addEntryPointFor(secondEntryPoint, neverMatch)
			.build();

		result.commence(this.request, null, null);

		verify(firstEntryPoint).commence(any(), any(), any());
		verifyNoInteractions(secondEntryPoint);
	}

	@Test
	@SuppressWarnings("removal")
	void builderWhenDefaultAndEmptyEntryPointsThenReturnsDefault() {
		AuthenticationEntryPoint defaultEntryPoint = mock(AuthenticationEntryPoint.class);

		AuthenticationEntryPoint result = DelegatingAuthenticationEntryPoint.builder()
			.defaultEntryPoint(defaultEntryPoint)
			.build();

		assertThat(result).isEqualTo(defaultEntryPoint);
	}

	@Test
	@SuppressWarnings("removal")
	void builderWhenNoEntryPointsThenIllegalStateException() {
		DelegatingAuthenticationEntryPoint.Builder builder = DelegatingAuthenticationEntryPoint.builder();
		assertThatIllegalStateException().isThrownBy(builder::build);
	}

}
