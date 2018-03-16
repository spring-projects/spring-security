/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web;

import java.util.Base64;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationException;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DefaultBearerTokenResolver}.
 *
 * @author Vedran Pavic
 */
public class DefaultBearerTokenResolverTests {

	private static final String TEST_TOKEN = "test-token";

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	private DefaultBearerTokenResolver resolver;

	@Before
	public void setUp() {
		this.resolver = new DefaultBearerTokenResolver();
	}

	@Test
	public void resolveWhenValidHeaderIsPresentThenTokenIsResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isEqualTo(TEST_TOKEN);
	}

	@Test
	public void resolveWhenNoHeaderIsPresentThenTokenIsNotResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();

		assertThat(this.resolver.resolve(request)).isNull();
	}

	@Test
	public void resolveWhenHeaderWithWrongSchemeIsPresentThenTokenIsNotResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Basic " + Base64.getEncoder().encodeToString("test:test".getBytes()));

		assertThat(this.resolver.resolve(request)).isNull();
	}

	@Test
	public void resolveWhenValidHeaderIsPresentTogetherWithFormParameterThenAuthenticationExceptionIsThrown() {
		this.thrown.expect(BearerTokenAuthenticationException.class);
		this.thrown.expectMessage("[invalid_request]");

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + TEST_TOKEN);
		request.setMethod("POST");
		request.setContentType("application/x-www-form-urlencoded");
		request.addParameter("access_token", TEST_TOKEN);

		this.resolver.resolve(request);
	}

	@Test
	public void resolveWhenValidHeaderIsPresentTogetherWithQueryParameterThenAuthenticationExceptionIsThrown() {
		this.thrown.expect(BearerTokenAuthenticationException.class);
		this.thrown.expectMessage("[invalid_request]");

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.addHeader("Authorization", "Bearer " + TEST_TOKEN);
		request.setMethod("GET");
		request.addParameter("access_token", TEST_TOKEN);

		this.resolver.resolve(request);
	}

	@Test
	public void resolveWhenFormParameterIsPresentAndSupportedThenTokenIsNotResolved() {
		this.resolver.setUseFormEncodedBodyParameter(true);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setContentType("application/x-www-form-urlencoded");
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isEqualTo(TEST_TOKEN);
	}

	@Test
	public void resolveWhenFormParameterIsPresentAndNotSupportedThenTokenIsNotResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("POST");
		request.setContentType("application/x-www-form-urlencoded");
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isNull();
	}

	@Test
	public void resolveWhenQueryParameterIsPresentAndSupportedThenTokenIsNotResolved() {
		this.resolver.setUseUriQueryParameter(true);

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("GET");
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isEqualTo(TEST_TOKEN);
	}

	@Test
	public void resolveWhenQueryParameterIsPresentAndNotSupportedThenTokenIsNotResolved() {
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setMethod("GET");
		request.addParameter("access_token", TEST_TOKEN);

		assertThat(this.resolver.resolve(request)).isNull();
	}

}
