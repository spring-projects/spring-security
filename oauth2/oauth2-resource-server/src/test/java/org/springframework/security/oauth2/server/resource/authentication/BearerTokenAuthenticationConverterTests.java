/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.server.resource.authentication;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.http.HttpHeaders;
import org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link BearerTokenAuthenticationConverter}
 *
 * @author Jeongjin Kim
 * @since 5.5
 */
@RunWith(MockitoJUnitRunner.class)
public class BearerTokenAuthenticationConverterTests {

	private BearerTokenAuthenticationConverter converter;

	@Before
	public void setup() {
		this.converter = new BearerTokenAuthenticationConverter();
	}

	@Test
	public void setBearerTokenResolverWithNullThenThrowsException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.converter.setBearerTokenResolver(null))
				.withMessageContaining("bearerTokenResolver cannot be null");
		// @formatter:on
	}

	@Test
	public void setAuthenticationDetailsSourceWithNullThenThrowsException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.converter.setAuthenticationDetailsSource(null))
				.withMessageContaining("authenticationDetailsSource cannot be null");
		// @formatter:on
	}

	@Test
	public void convertWhenNoBearerTokenHeaderThenNull() {
		HttpServletRequest request = mock(HttpServletRequest.class);

		BearerTokenAuthenticationToken convert = this.converter.convert(request);

		assertThat(convert).isNull();
	}

	@Test
	public void convertWhenBearerTokenThenBearerTokenAuthenticationToken() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		given(request.getHeader(HttpHeaders.AUTHORIZATION)).willReturn("Bearer token");

		BearerTokenAuthenticationToken token = this.converter.convert(request);

		assertThat(token.getToken()).isEqualTo("token");
	}

}
