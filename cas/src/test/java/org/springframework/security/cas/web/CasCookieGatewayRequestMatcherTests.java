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

package org.springframework.security.cas.web;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import org.apereo.cas.client.authentication.DefaultGatewayResolverImpl;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;

/**
 * Tests {@link CasCookieGatewayRequestMatche}.
 *
 * @author Michael Remond
 */
public class CasCookieGatewayRequestMatcherTests {

	@Test
	public void testNullServiceProperties() throws Exception {
		try {
			new CasCookieGatewayRequestMatcher(null, null);
			fail("Should have thrown IllegalArgumentException");
		}
		catch (IllegalArgumentException expected) {
			assertThat(expected.getMessage()).isEqualTo("serviceProperties cannot be null");
		}
	}

	@Test
	public void testNormalOperationWithNoSSOSession() throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(null);
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setService("http://localhost/j_spring_cas_security_check");
		CasCookieGatewayRequestMatcher rm = new CasCookieGatewayRequestMatcher(serviceProperties, null);
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");

		// First request
		assertThat(rm.matches(request)).isTrue();
		assertThat(request.getSession(false).getAttribute(DefaultGatewayResolverImpl.CONST_CAS_GATEWAY)).isNotNull();
		// Second request
		assertThat(rm.matches(request)).isFalse();
		assertThat(request.getSession(false).getAttribute(DefaultGatewayResolverImpl.CONST_CAS_GATEWAY)).isNotNull();
	}

	@Test
	public void testGatewayWhenCasAuthenticated() throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(null);
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setService("http://localhost/j_spring_cas_security_check");
		CasCookieGatewayRequestMatcher rm = new CasCookieGatewayRequestMatcher(serviceProperties,
				"CAS_TGT_COOKIE_TEST_NAME");
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");
		request.setCookies(new Cookie("CAS_TGT_COOKIE_TEST_NAME", "casTGCookieValue"));

		assertThat(rm.matches(request)).isTrue();

		MockHttpServletRequest requestWithoutCasCookie = new MockHttpServletRequest("GET", "/some_path");
		requestWithoutCasCookie.setCookies(new Cookie("WRONG_CAS_TGT_COOKIE_TEST_NAME", "casTGCookieValue"));

		assertThat(rm.matches(requestWithoutCasCookie)).isFalse();
	}

	@Test
	public void testGatewayWhenAlreadySessionCreated() throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(mock(CasAuthenticationToken.class));

		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setService("http://localhost/j_spring_cas_security_check");
		CasCookieGatewayRequestMatcher rm = new CasCookieGatewayRequestMatcher(serviceProperties,
				"CAS_TGT_COOKIE_TEST_NAME");
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");
		assertThat(rm.matches(request)).isFalse();
	}

	@Test
	public void testGatewayWithNoMatchingRequest() throws IOException, ServletException {
		SecurityContextHolder.getContext().setAuthentication(null);
		ServiceProperties serviceProperties = new ServiceProperties();
		serviceProperties.setService("http://localhost/j_spring_cas_security_check");
		CasCookieGatewayRequestMatcher rm = new CasCookieGatewayRequestMatcher(serviceProperties,
				"CAS_TGT_COOKIE_TEST_NAME") {
			@Override
			protected boolean performGatewayAuthentication(HttpServletRequest request) {
				return false;
			}
		};
		MockHttpServletRequest request = new MockHttpServletRequest("GET", "/some_path");

		assertThat(rm.matches(request)).isFalse();
	}

}
