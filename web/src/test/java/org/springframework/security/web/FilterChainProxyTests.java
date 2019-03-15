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
package org.springframework.security.web;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.invocation.InvocationOnMock;
import org.mockito.stubbing.Answer;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;
import java.util.*;

/**
 * @author Luke Taylor
 * @author Rob Winch
 */
public class FilterChainProxyTests {
	private FilterChainProxy fcp;
	private RequestMatcher matcher;
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;
	private FilterChain chain;
	private Filter filter;

	@Before
	public void setup() throws Exception {
		matcher = mock(RequestMatcher.class);
		filter = mock(Filter.class);
		doAnswer(new Answer<Object>() {
			public Object answer(InvocationOnMock inv) throws Throwable {
				Object[] args = inv.getArguments();
				FilterChain fc = (FilterChain) args[2];
				HttpServletRequestWrapper extraWrapper = new HttpServletRequestWrapper(
						(HttpServletRequest) args[0]);
				fc.doFilter(extraWrapper, (HttpServletResponse) args[1]);
				return null;
			}
		}).when(filter).doFilter(any(),
				any(), any());
		fcp = new FilterChainProxy(new DefaultSecurityFilterChain(matcher,
				Arrays.asList(filter)));
		fcp.setFilterChainValidator(mock(FilterChainProxy.FilterChainValidator.class));
		request = new MockHttpServletRequest("GET", "");
		request.setServletPath("/path");
		response = new MockHttpServletResponse();
		chain = mock(FilterChain.class);
	}

	@After
	public void teardown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void toStringCallSucceeds() throws Exception {
		fcp.afterPropertiesSet();
		fcp.toString();
	}

	@Test
	public void securityFilterChainIsNotInvokedIfMatchFails() throws Exception {
		when(matcher.matches(any(HttpServletRequest.class))).thenReturn(false);
		fcp.doFilter(request, response, chain);
		assertThat(fcp.getFilterChains()).hasSize(1);
		assertThat(fcp.getFilterChains().get(0).getFilters().get(0)).isSameAs(filter);

		verifyZeroInteractions(filter);
		// The actual filter chain should be invoked though
		verify(chain).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void originalChainIsInvokedAfterSecurityChainIfMatchSucceeds()
			throws Exception {
		when(matcher.matches(any(HttpServletRequest.class))).thenReturn(true);
		fcp.doFilter(request, response, chain);

		verify(filter).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(FilterChain.class));
		verify(chain).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void originalFilterChainIsInvokedIfMatchingSecurityChainIsEmpty()
			throws Exception {
		List<Filter> noFilters = Collections.emptyList();
		fcp = new FilterChainProxy(new DefaultSecurityFilterChain(matcher, noFilters));

		when(matcher.matches(any(HttpServletRequest.class))).thenReturn(true);
		fcp.doFilter(request, response, chain);

		verify(chain).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void requestIsWrappedForMatchingAndFilteringWhenMatchIsFound()
			throws Exception {
		when(matcher.matches(any())).thenReturn(true);
		fcp.doFilter(request, response, chain);
		verify(matcher).matches(any(FirewalledRequest.class));
		verify(filter).doFilter(any(FirewalledRequest.class),
				any(HttpServletResponse.class), any(FilterChain.class));
		verify(chain).doFilter(any(),
				any(HttpServletResponse.class));
	}

	@Test
	public void requestIsWrappedForMatchingAndFilteringWhenMatchIsNotFound()
			throws Exception {
		when(matcher.matches(any(HttpServletRequest.class))).thenReturn(false);
		fcp.doFilter(request, response, chain);
		verify(matcher).matches(any(FirewalledRequest.class));
		verifyZeroInteractions(filter);
		verify(chain).doFilter(any(FirewalledRequest.class),
				any(HttpServletResponse.class));
	}

	@Test
	public void wrapperIsResetWhenNoMatchingFilters() throws Exception {
		HttpFirewall fw = mock(HttpFirewall.class);
		FirewalledRequest fwr = mock(FirewalledRequest.class);
		when(fwr.getRequestURI()).thenReturn("/");
		when(fwr.getContextPath()).thenReturn("");
		fcp.setFirewall(fw);
		when(fw.getFirewalledRequest(request)).thenReturn(fwr);
		when(matcher.matches(any(HttpServletRequest.class))).thenReturn(false);
		fcp.doFilter(request, response, chain);
		verify(fwr).reset();
	}

	// SEC-1639
	@Test
	public void bothWrappersAreResetWithNestedFcps() throws Exception {
		HttpFirewall fw = mock(HttpFirewall.class);
		FilterChainProxy firstFcp = new FilterChainProxy(new DefaultSecurityFilterChain(
				matcher, fcp));
		firstFcp.setFirewall(fw);
		fcp.setFirewall(fw);
		FirewalledRequest firstFwr = mock(FirewalledRequest.class, "firstFwr");
		when(firstFwr.getRequestURI()).thenReturn("/");
		when(firstFwr.getContextPath()).thenReturn("");
		FirewalledRequest fwr = mock(FirewalledRequest.class, "fwr");
		when(fwr.getRequestURI()).thenReturn("/");
		when(fwr.getContextPath()).thenReturn("");
		when(fw.getFirewalledRequest(request)).thenReturn(firstFwr);
		when(fw.getFirewalledRequest(firstFwr)).thenReturn(fwr);
		when(fwr.getRequest()).thenReturn(firstFwr);
		when(firstFwr.getRequest()).thenReturn(request);
		when(matcher.matches(any())).thenReturn(true);
		firstFcp.doFilter(request, response, chain);
		verify(firstFwr).reset();
		verify(fwr).reset();
	}

	@Test
	public void doFilterClearsSecurityContextHolder() throws Exception {
		when(matcher.matches(any(HttpServletRequest.class))).thenReturn(true);
		doAnswer(new Answer<Object>() {
			public Object answer(InvocationOnMock inv) throws Throwable {
				SecurityContextHolder.getContext().setAuthentication(
						new TestingAuthenticationToken("username", "password"));
				return null;
			}
		}).when(filter).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(FilterChain.class));

		fcp.doFilter(request, response, chain);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void doFilterClearsSecurityContextHolderWithException() throws Exception {
		when(matcher.matches(any(HttpServletRequest.class))).thenReturn(true);
		doAnswer(new Answer<Object>() {
			public Object answer(InvocationOnMock inv) throws Throwable {
				SecurityContextHolder.getContext().setAuthentication(
						new TestingAuthenticationToken("username", "password"));
				throw new ServletException("oops");
			}
		}).when(filter).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(FilterChain.class));

		try {
			fcp.doFilter(request, response, chain);
			fail("Expected Exception");
		}
		catch (ServletException success) {
		}

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	// SEC-2027
	@Test
	public void doFilterClearsSecurityContextHolderOnceOnForwards() throws Exception {
		final FilterChain innerChain = mock(FilterChain.class);
		when(matcher.matches(any(HttpServletRequest.class))).thenReturn(true);
		doAnswer(new Answer<Object>() {
			public Object answer(InvocationOnMock inv) throws Throwable {
				TestingAuthenticationToken expected = new TestingAuthenticationToken(
						"username", "password");
				SecurityContextHolder.getContext().setAuthentication(expected);
				doAnswer(new Answer<Object>() {
					public Object answer(InvocationOnMock inv) throws Throwable {
						innerChain.doFilter(request, response);
						return null;
					}
				}).when(filter).doFilter(any(HttpServletRequest.class),
						any(HttpServletResponse.class), any(FilterChain.class));

				fcp.doFilter(request, response, innerChain);
				assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(expected);
				return null;
			}
		}).when(filter).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(FilterChain.class));

		fcp.doFilter(request, response, chain);

		verify(innerChain).doFilter(any(HttpServletRequest.class),
				any(HttpServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}
}
