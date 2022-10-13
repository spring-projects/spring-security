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
import java.util.function.Supplier;

import jakarta.servlet.Filter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.FilterConfig;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.MockSecurityContextHolderStrategy;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * Tests {@link AnonymousAuthenticationFilter}.
 *
 * @author Ben Alex
 * @author Eddú Meléndez
 * @author Evgeniy Cheban
 */
public class AnonymousAuthenticationFilterTests {

	private void executeFilterInContainerSimulator(FilterConfig filterConfig, Filter filter, ServletRequest request,
			ServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		filter.doFilter(request, response, filterChain);
	}

	@BeforeEach
	@AfterEach
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void testDetectsMissingKey() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AnonymousAuthenticationFilter(null));
	}

	@Test
	public void testDetectsUserAttribute() {
		assertThatIllegalArgumentException().isThrownBy(() -> new AnonymousAuthenticationFilter("qwerty", null, null));
	}

	@Test
	public void testOperationWhenAuthenticationExistsInContextHolder() throws Exception {
		// Put an Authentication object into the SecurityContextHolder
		Authentication originalAuth = new TestingAuthenticationToken("user", "password", "ROLE_A");
		SecurityContext originalContext = new SecurityContextImpl(originalAuth);
		SecurityContextHolder.setContext(originalContext);
		AnonymousAuthenticationFilter filter = new AnonymousAuthenticationFilter("qwerty", "anonymousUsername",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.setRequestURI("x");
		executeFilterInContainerSimulator(mock(FilterConfig.class), filter, request, new MockHttpServletResponse(),
				new MockFilterChain(true));
		// Ensure getDeferredContext still
		assertThat(SecurityContextHolder.getContext()).isEqualTo(originalContext);
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

	@Test
	public void doFilterDoesNotGetContext() throws Exception {
		Supplier<SecurityContext> originalSupplier = mock(Supplier.class);
		Authentication originalAuth = new TestingAuthenticationToken("user", "password", "ROLE_A");
		SecurityContext originalContext = new SecurityContextImpl(originalAuth);
		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getDeferredContext()).willReturn(originalSupplier);
		given(strategy.getContext()).willReturn(originalContext);
		AnonymousAuthenticationFilter filter = new AnonymousAuthenticationFilter("qwerty", "anonymousUsername",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		filter.setSecurityContextHolderStrategy(strategy);
		filter.afterPropertiesSet();

		executeFilterInContainerSimulator(mock(FilterConfig.class), filter, new MockHttpServletRequest(),
				new MockHttpServletResponse(), new MockFilterChain(true));
		verify(strategy, never()).getContext();
		verify(originalSupplier, never()).get();
	}

	@Test
	public void doFilterSetsSingletonSupplier() throws Exception {
		Supplier<SecurityContext> originalSupplier = mock(Supplier.class);
		Authentication originalAuth = new TestingAuthenticationToken("user", "password", "ROLE_A");
		SecurityContext originalContext = new SecurityContextImpl(originalAuth);
		SecurityContextHolderStrategy strategy = new MockSecurityContextHolderStrategy(originalSupplier);
		given(originalSupplier.get()).willReturn(originalContext);
		AnonymousAuthenticationFilter filter = new AnonymousAuthenticationFilter("qwerty", "anonymousUsername",
				AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		filter.setSecurityContextHolderStrategy(strategy);
		filter.afterPropertiesSet();
		executeFilterInContainerSimulator(mock(FilterConfig.class), filter, new MockHttpServletRequest(),
				new MockHttpServletResponse(), new MockFilterChain(true));
		Supplier<SecurityContext> deferredContext = strategy.getDeferredContext();
		deferredContext.get();
		deferredContext.get();
		verify(originalSupplier, times(1)).get();
	}

	private class MockFilterChain implements FilterChain {

		private boolean expectToProceed;

		MockFilterChain(boolean expectToProceed) {
			this.expectToProceed = expectToProceed;
		}

		@Override
		public void doFilter(ServletRequest request, ServletResponse response) {
			if (!this.expectToProceed) {
				fail("Did not expect filter chain to proceed");
			}
		}

	}

}
