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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.springframework.mock.web.MockHttpServletResponse;

import static org.mockito.Mockito.when;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.times;

/**
 * @author Takuya Iwatsuka
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class SignedRedirectHttpServletResponseTests {

	@Mock
	SignCalculator signCalculator;

	MockHttpServletResponse response;

	Set<String> excludedURLs;

	@Before
	public void SetupBlock(){
		this.response = new MockHttpServletResponse();
		this.excludedURLs = Collections.emptySet();
	}

	@Test(expected = InvalidRedirectException.class)
	public void sendRedirectThrowsExceptionIfSignIsMissing() throws IOException {
		String targetURL = "https://spring.io";
		SignedRedirectHttpServletResponse signedResponse = new SignedRedirectHttpServletResponse(
				this.response, null, signCalculator, excludedURLs);
		signedResponse.sendRedirect(targetURL);
	}

	@Test(expected = InvalidRedirectException.class)
	public void sendRedirectThrowsExceptionIfSignIsInvalid() throws IOException {
		String targetURL = "https://spring.io";
		String sign = "invalid_sign";
		when(this.signCalculator.validateSign(targetURL, sign)).thenReturn(false);

		SignedRedirectHttpServletResponse signedResponse = new SignedRedirectHttpServletResponse(
				this.response, sign, this.signCalculator, excludedURLs);
		signedResponse.sendRedirect(targetURL);
	}

	@Test
	public void sendRedirectIfSignIsValid() throws IOException {
		String targetURL = "https://spring.io";
		String sign = "valid_sign";
		when(this.signCalculator.validateSign(targetURL, sign)).thenReturn(true);

		SignedRedirectHttpServletResponse signedResponse = new SignedRedirectHttpServletResponse(
				this.response, sign, this.signCalculator, excludedURLs);
		signedResponse.sendRedirect(targetURL);

		verify(this.signCalculator, times(1)).validateSign(targetURL, sign);
	}

	@Test(expected = InvalidRedirectException.class)
	public void sendRedirectThrowsExceptionIfTargetURLIsNotMatch() throws IOException {
		String targetURL = "https://spring.io";
		String sign = "invalid_sign";
		when(this.signCalculator.validateSign(targetURL, sign)).thenReturn(false);

		String location = "https://some.location";
		SignedRedirectHttpServletResponse signedResponse = new SignedRedirectHttpServletResponse(
				this.response, sign, this.signCalculator, excludedURLs);
		signedResponse.sendRedirect(location);
	}

	@Test
	public void sendRedirectDoesNotVelifyIfTargetURLIsExcluded() throws IOException {
		String targetURL = "https://spring.io";
		String sign = "invalid_sign";
		when(this.signCalculator.validateSign(targetURL, sign)).thenReturn(false);

		String location = "https://some.location";
		this.excludedURLs = new HashSet<String>(Arrays.asList(location));
		SignedRedirectHttpServletResponse signedResponse = new SignedRedirectHttpServletResponse(
				this.response, sign, this.signCalculator, excludedURLs);
		signedResponse.sendRedirect(location);

		verify(this.signCalculator, times(0)).validateSign(location, sign);
	}
}
