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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletRequestWrapper;
import javax.servlet.http.HttpServletResponse;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.stubbing.Answer;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.firewall.FirewalledRequest;
import org.springframework.security.web.firewall.HttpFirewall;
import org.springframework.security.web.firewall.RequestRejectedException;
import org.springframework.security.web.firewall.RequestRejectedHandler;
import org.springframework.security.web.util.matcher.RequestMatcher;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

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
		this.matcher = mock(RequestMatcher.class);
		this.filter = mock(Filter.class);
		willAnswer((Answer<Object>) inv -> {
			Object[] args = inv.getArguments();
			FilterChain fc = (FilterChain) args[2];
			HttpServletRequestWrapper extraWrapper = new HttpServletRequestWrapper((HttpServletRequest) args[0]);
			fc.doFilter(extraWrapper, (HttpServletResponse) args[1]);
			return null;
		}).given(this.filter).doFilter(any(), any(), any());
		this.fcp = new FilterChainProxy(new DefaultSecurityFilterChain(this.matcher, Arrays.asList(this.filter)));
		this.fcp.setFilterChainValidator(mock(FilterChainProxy.FilterChainValidator.class));
		this.request = new MockHttpServletRequest("GET", "");
		this.request.setServletPath("/path");
		this.response = new MockHttpServletResponse();
		this.chain = mock(FilterChain.class);
	}

	@After
	public void teardown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void toStringCallSucceeds() {
		this.fcp.afterPropertiesSet();
		this.fcp.toString();
	}

	@Test
	public void securityFilterChainIsNotInvokedIfMatchFails() throws Exception {
		given(this.matcher.matches(any(HttpServletRequest.class))).willReturn(false);
		this.fcp.doFilter(this.request, this.response, this.chain);
		assertThat(this.fcp.getFilterChains()).hasSize(1);
		assertThat(this.fcp.getFilterChains().get(0).getFilters().get(0)).isSameAs(this.filter);

		verifyZeroInteractions(this.filter);
		// The actual filter chain should be invoked though
		verify(this.chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void originalChainIsInvokedAfterSecurityChainIfMatchSucceeds() throws Exception {
		given(this.matcher.matches(any(HttpServletRequest.class))).willReturn(true);
		this.fcp.doFilter(this.request, this.response, this.chain);

		verify(this.filter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(FilterChain.class));
		verify(this.chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void originalFilterChainIsInvokedIfMatchingSecurityChainIsEmpty() throws Exception {
		List<Filter> noFilters = Collections.emptyList();
		this.fcp = new FilterChainProxy(new DefaultSecurityFilterChain(this.matcher, noFilters));

		given(this.matcher.matches(any(HttpServletRequest.class))).willReturn(true);
		this.fcp.doFilter(this.request, this.response, this.chain);

		verify(this.chain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void requestIsWrappedForMatchingAndFilteringWhenMatchIsFound() throws Exception {
		given(this.matcher.matches(any())).willReturn(true);
		this.fcp.doFilter(this.request, this.response, this.chain);
		verify(this.matcher).matches(any(FirewalledRequest.class));
		verify(this.filter).doFilter(any(FirewalledRequest.class), any(HttpServletResponse.class),
				any(FilterChain.class));
		verify(this.chain).doFilter(any(), any(HttpServletResponse.class));
	}

	@Test
	public void requestIsWrappedForMatchingAndFilteringWhenMatchIsNotFound() throws Exception {
		given(this.matcher.matches(any(HttpServletRequest.class))).willReturn(false);
		this.fcp.doFilter(this.request, this.response, this.chain);
		verify(this.matcher).matches(any(FirewalledRequest.class));
		verifyZeroInteractions(this.filter);
		verify(this.chain).doFilter(any(FirewalledRequest.class), any(HttpServletResponse.class));
	}

	@Test
	public void wrapperIsResetWhenNoMatchingFilters() throws Exception {
		HttpFirewall fw = mock(HttpFirewall.class);
		FirewalledRequest fwr = mock(FirewalledRequest.class);
		given(fwr.getRequestURI()).willReturn("/");
		given(fwr.getContextPath()).willReturn("");
		this.fcp.setFirewall(fw);
		given(fw.getFirewalledRequest(this.request)).willReturn(fwr);
		given(this.matcher.matches(any(HttpServletRequest.class))).willReturn(false);
		this.fcp.doFilter(this.request, this.response, this.chain);
		verify(fwr).reset();
	}

	// SEC-1639
	@Test
	public void bothWrappersAreResetWithNestedFcps() throws Exception {
		HttpFirewall fw = mock(HttpFirewall.class);
		FilterChainProxy firstFcp = new FilterChainProxy(new DefaultSecurityFilterChain(this.matcher, this.fcp));
		firstFcp.setFirewall(fw);
		this.fcp.setFirewall(fw);
		FirewalledRequest firstFwr = mock(FirewalledRequest.class, "firstFwr");
		given(firstFwr.getRequestURI()).willReturn("/");
		given(firstFwr.getContextPath()).willReturn("");
		FirewalledRequest fwr = mock(FirewalledRequest.class, "fwr");
		given(fwr.getRequestURI()).willReturn("/");
		given(fwr.getContextPath()).willReturn("");
		given(fw.getFirewalledRequest(this.request)).willReturn(firstFwr);
		given(fw.getFirewalledRequest(firstFwr)).willReturn(fwr);
		given(fwr.getRequest()).willReturn(firstFwr);
		given(firstFwr.getRequest()).willReturn(this.request);
		given(this.matcher.matches(any())).willReturn(true);
		firstFcp.doFilter(this.request, this.response, this.chain);
		verify(firstFwr).reset();
		verify(fwr).reset();
	}

	@Test
	public void doFilterClearsSecurityContextHolder() throws Exception {
		given(this.matcher.matches(any(HttpServletRequest.class))).willReturn(true);
		willAnswer((Answer<Object>) inv -> {
			SecurityContextHolder.getContext()
					.setAuthentication(new TestingAuthenticationToken("username", "password"));
			return null;
		}).given(this.filter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(FilterChain.class));

		this.fcp.doFilter(this.request, this.response, this.chain);

		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test
	public void doFilterClearsSecurityContextHolderWithException() throws Exception {
		given(this.matcher.matches(any(HttpServletRequest.class))).willReturn(true);
		willAnswer((Answer<Object>) inv -> {
			SecurityContextHolder.getContext()
					.setAuthentication(new TestingAuthenticationToken("username", "password"));
			throw new ServletException("oops");
		}).given(this.filter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(FilterChain.class));

		try {
			this.fcp.doFilter(this.request, this.response, this.chain);
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
		given(this.matcher.matches(any(HttpServletRequest.class))).willReturn(true);
		willAnswer((Answer<Object>) inv -> {
			TestingAuthenticationToken expected = new TestingAuthenticationToken("username", "password");
			SecurityContextHolder.getContext().setAuthentication(expected);
			willAnswer((Answer<Object>) inv1 -> {
				innerChain.doFilter(this.request, this.response);
				return null;
			}).given(this.filter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class),
					any(FilterChain.class));

			this.fcp.doFilter(this.request, this.response, innerChain);
			assertThat(SecurityContextHolder.getContext().getAuthentication()).isSameAs(expected);
			return null;
		}).given(this.filter).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(FilterChain.class));

		this.fcp.doFilter(this.request, this.response, this.chain);

		verify(innerChain).doFilter(any(HttpServletRequest.class), any(HttpServletResponse.class));
		assertThat(SecurityContextHolder.getContext().getAuthentication()).isNull();
	}

	@Test(expected = IllegalArgumentException.class)
	public void setRequestRejectedHandlerDoesNotAcceptNull() {
		this.fcp.setRequestRejectedHandler(null);
	}

	@Test
	public void requestRejectedHandlerIsCalledIfFirewallThrowsRequestRejectedException() throws Exception {
		HttpFirewall fw = mock(HttpFirewall.class);
		RequestRejectedHandler rjh = mock(RequestRejectedHandler.class);
		this.fcp.setFirewall(fw);
		this.fcp.setRequestRejectedHandler(rjh);
		RequestRejectedException requestRejectedException = new RequestRejectedException("Contains illegal chars");
		given(fw.getFirewalledRequest(this.request)).willThrow(requestRejectedException);
		this.fcp.doFilter(this.request, this.response, this.chain);
		verify(rjh).handle(eq(this.request), eq(this.response), eq((requestRejectedException)));
	}

}
