/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.Mockito.mock;

/**
 * Tests {@link AnonymousAuthenticationFilter}.
 *
 * @author Ben Alex
 * @author Eddú Meléndez
 */
public class AnonymousAuthenticationFilterTests {

	private void executeFilterInContainerSimulator(FilterConfig filterConfig, Filter filter, ServletRequest request,
			ServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		filter.doFilter(request, response, filterChain);
	}

	@Before
	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDetectsMissingKey() {
		new AnonymousAuthenticationFilter(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void testDetectsUserAttribute() {
		new AnonymousAuthenticationFilter("qwerty", null, null);
	}

	@Test
	public void testOperationWhenAuthenticationExistsInContextHolder() throws Exception {
		// Put an Authentication object into the SecurityContextHolder
		Authentication originalAuth = new TestingAuthenticationToken("user", "password", "ROLE_A");
		SecurityContextHolder.getContext().setAuthentication(originalAuth);

		AnonymousAuthenticationFilter filter = new AnonymousAuthenticationFilter("qwerty", "anonymousUsername",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

		// Test
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("x");
		executeFilterInContainerSimulator(mock(FilterConfig.class), filter, request, new MockHttpServletResponse(),
				new MockFilterChain(true));

		// Ensure filter didn't change our original object
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isEqualTo(originalAuth);
	}

	@Test
	public void testOperationWhenNoAuthenticationInSecurityContextHolder() throws Exception {
		AnonymousAuthenticationFilter filter = new AnonymousAuthenticationFilter("qwerty", "anonymousUsername",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		filter.afterPropertiesSet();

		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("x");
		executeFilterInContainerSimulator(mock(FilterConfig.class), filter, request, new MockHttpServletResponse(),
				new MockFilterChain(true));

		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		assertThat(auth.getPrincipal()).isEqualTo("anonymousUsername");
		assertThat(AuthorityUtils.authorityListToSet(auth.getAuthorities())).contains("ROLE_ANONYMOUS");
		SecurityContextHolder.getContext().setAuthentication(null); // so anonymous fires
																	// again
	}

	private class MockFilterChain implements FilterChain {

		private boolean expectToProceed;

		MockFilterChain(boolean expectToProceed) {
			this.expectToProceed = expectToProceed;
		}

		public void doFilter(ServletRequest request, ServletResponse response) {
			if (!this.expectToProceed) {
				fail("Did not expect filter chain to proceed");
			}
		}

	}

}
