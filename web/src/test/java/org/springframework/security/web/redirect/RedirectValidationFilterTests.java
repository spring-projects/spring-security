/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.redirect;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Matchers.any;

/**
 * @author Takuya Iwatsuka
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class RedirectValidationFilterTests {

	@Captor
	private ArgumentCaptor<HttpServletResponse> responseCaptor;

	@Mock
	private SignCalculator signCalculator;

	@Mock
	private FilterChain filterChain;

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private RedirectValidationFilter filter;

	@Before
	public void setup() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.filter = new RedirectValidationFilter(this.signCalculator);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullSignCalculator() {
		new RedirectValidationFilter(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setRedirectParameterNull() {
		this.filter.setRedirectParameter(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void setSignParameterNull() {
		this.filter.setSignParameter(null);
	}

	@Test
	public void doFilterSetRequestAttributes() throws ServletException,
			IOException {
		this.filter.doFilter(this.request, this.response, this.filterChain);
		assertThat(this.request.getAttribute("_redirectParameter")).isEqualTo(
				"redirectTo");
		assertThat(this.request.getAttribute("_signParameter")).isEqualTo(
				"sign");
		assertThat(this.request.getAttribute("_signCalculator")).isEqualTo(
				this.signCalculator);
	}

	@Test
	public void doFilterDoesNotWrapResponseIfRedirectParameterIsNotContained()
			throws ServletException, IOException{
		this.filter.doFilter(this.request, this.response, this.filterChain);
		verify(this.filterChain).doFilter(any(HttpServletRequest.class), this.responseCaptor.capture());
		assertThat(this.responseCaptor.getValue()).isNotInstanceOf(SignedRedirectHttpServletResponse.class);
	}

	@Test
	public void doFilterWrapResponseIfRedirectParameterIsContained()
			throws ServletException, IOException{
		this.request.setParameter("redirectTo", "https://spring.io/");
		this.filter.doFilter(this.request, this.response, this.filterChain);
		verify(this.filterChain).doFilter(any(HttpServletRequest.class), this.responseCaptor.capture());
		assertThat(this.responseCaptor.getValue()).isInstanceOf(SignedRedirectHttpServletResponse.class);
	}
}
