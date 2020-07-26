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
package org.springframework.security.web.context;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.junit.After;
import org.junit.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class SecurityContextPersistenceFilterTests {

	TestingAuthenticationToken testToken = new TestingAuthenticationToken("someone", "passwd", "ROLE_A");

	@After
	public void clearContext() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void contextIsClearedAfterChainProceeds() throws Exception {
		final FilterChain chain = mock(FilterChain.class);
		final MockHttpServletRequest request = new MockHttpServletRequest();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter();
		SecurityContextHolder.getContext().setAuthentication(this.testToken);

		filter.doFilter(request, response, chain);
		verify(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void contextIsStillClearedIfExceptionIsThrowByFilterChain() throws Exception {
		final FilterChain chain = mock(FilterChain.class);
		final MockHttpServletRequest request = new MockHttpServletRequest();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter();
		SecurityContextHolder.getContext().setAuthentication(this.testToken);
		doThrow(new IOException()).when(chain).doFilter(any(ServletRequest.class), any(ServletResponse.class));
		try {
			filter.doFilter(request, response, chain);
			fail("IOException should have been thrown");
		}
		catch (IOException expected) {
		}

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void loadedContextContextIsCopiedToSecurityContextHolderAndUpdatedContextIsStored() throws Exception {
		final MockHttpServletRequest request = new MockHttpServletRequest();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		final TestingAuthenticationToken beforeAuth = new TestingAuthenticationToken("someoneelse", "passwd", "ROLE_B");
		final SecurityContext scBefore = new SecurityContextImpl();
		final SecurityContext scExpectedAfter = new SecurityContextImpl();
		scExpectedAfter.setAuthentication(this.testToken);
		scBefore.setAuthentication(beforeAuth);
		final SecurityContextRepository repo = mock(SecurityContextRepository.class);
		SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter(repo);

		when(repo.loadContext(any(HttpRequestResponseHolder.class))).thenReturn(scBefore);

		final FilterChain chain = (request1, response1) -> {
			assertThat(SecurityContextHolder.getContext().getAuthentication()).isEqualTo(beforeAuth);
			// Change the context here
			SecurityContextHolder.setContext(scExpectedAfter);
		};

		filter.doFilter(request, response, chain);

		verify(repo).saveContext(scExpectedAfter, request, response);
	}

	@Test
	public void filterIsNotAppliedAgainIfFilterAppliedAttributeIsSet() throws Exception {
		final FilterChain chain = mock(FilterChain.class);
		final MockHttpServletRequest request = new MockHttpServletRequest();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter(
				mock(SecurityContextRepository.class));

		request.setAttribute(SecurityContextPersistenceFilter.FILTER_APPLIED, Boolean.TRUE);
		filter.doFilter(request, response, chain);
		verify(chain).doFilter(request, response);
	}

	@Test
	public void sessionIsEagerlyCreatedWhenConfigured() throws Exception {
		final FilterChain chain = mock(FilterChain.class);
		final MockHttpServletRequest request = new MockHttpServletRequest();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter();
		filter.setForceEagerSessionCreation(true);
		filter.doFilter(request, response, chain);
		assertThat(request.getSession(false)).isNotNull();
	}

	@Test
	public void nullSecurityContextRepoDoesntSaveContextOrCreateSession() throws Exception {
		final FilterChain chain = mock(FilterChain.class);
		final MockHttpServletRequest request = new MockHttpServletRequest();
		final MockHttpServletResponse response = new MockHttpServletResponse();
		SecurityContextRepository repo = new NullSecurityContextRepository();
		SecurityContextPersistenceFilter filter = new SecurityContextPersistenceFilter(repo);
		filter.doFilter(request, response, chain);
		assertThat(repo.containsContext(request)).isFalse();
		assertThat(request.getSession(false)).isNull();
	}

}
