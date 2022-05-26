/*
 * Copyright 2002-2022 the original author or authors.
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

package org.springframework.security.web.access.intercept;

import java.util.function.Supplier;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;
import org.springframework.web.util.WebUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Tests for {@link AuthorizationFilter}.
 *
 * @author Evgeniy Cheban
 */
public class AuthorizationFilterTests {

	@AfterEach
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void filterWhenAuthorizationManagerVerifyPassesThenNextFilter() throws Exception {
		AuthorizationManager<HttpServletRequest> mockAuthorizationManager = mock(AuthorizationManager.class);
		given(mockAuthorizationManager.check(any(Supplier.class), any(HttpServletRequest.class)))
				.willReturn(new AuthorizationDecision(true));
		AuthorizationFilter filter = new AuthorizationFilter(mockAuthorizationManager);
		TestingAuthenticationToken authenticationToken = new TestingAuthenticationToken("user", "password");

		SecurityContextHolderStrategy strategy = mock(SecurityContextHolderStrategy.class);
		given(strategy.getContext()).willReturn(new SecurityContextImpl(authenticationToken));
		filter.setSecurityContextHolderStrategy(strategy);

		MockHttpServletRequest mockRequest = new MockHttpServletRequest(null, "/path");
		MockHttpServletResponse mockResponse = new MockHttpServletResponse();
		FilterChain mockFilterChain = mock(FilterChain.class);

		filter.doFilter(mockRequest, mockResponse, mockFilterChain);

		ArgumentCaptor<Supplier<Authentication>> authenticationCaptor = ArgumentCaptor.forClass(Supplier.class);
		verify(mockAuthorizationManager).check(authenticationCaptor.capture(), eq(mockRequest));
		Supplier<Authentication> authentication = authenticationCaptor.getValue();
		assertThat(authentication.get()).isEqualTo(authenticationToken);

		verify(mockFilterChain).doFilter(mockRequest, mockResponse);
		verify(strategy).getContext();
	}

	@Test
	public void filterWhenAuthorizationManagerVerifyThrowsAccessDeniedExceptionThenStopFilterChain() {
		AuthorizationManager<HttpServletRequest> mockAuthorizationManager = mock(AuthorizationManager.class);
		AuthorizationFilter filter = new AuthorizationFilter(mockAuthorizationManager);
		TestingAuthenticationToken authenticationToken = new TestingAuthenticationToken("user", "password");

		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(authenticationToken);
		SecurityContextHolder.setContext(securityContext);

		MockHttpServletRequest mockRequest = new MockHttpServletRequest(null, "/path");
		MockHttpServletResponse mockResponse = new MockHttpServletResponse();
		FilterChain mockFilterChain = mock(FilterChain.class);

		willThrow(new AccessDeniedException("Access Denied")).given(mockAuthorizationManager).check(any(),
				eq(mockRequest));

		assertThatExceptionOfType(AccessDeniedException.class)
				.isThrownBy(() -> filter.doFilter(mockRequest, mockResponse, mockFilterChain))
				.withMessage("Access Denied");

		ArgumentCaptor<Supplier<Authentication>> authenticationCaptor = ArgumentCaptor.forClass(Supplier.class);
		verify(mockAuthorizationManager).check(authenticationCaptor.capture(), eq(mockRequest));
		Supplier<Authentication> authentication = authenticationCaptor.getValue();
		assertThat(authentication.get()).isEqualTo(authenticationToken);

		verifyNoInteractions(mockFilterChain);
	}

	@Test
	public void filterWhenAuthenticationNullThenAuthenticationCredentialsNotFoundException() {
		AuthorizationFilter filter = new AuthorizationFilter(AuthenticatedAuthorizationManager.authenticated());
		MockHttpServletRequest mockRequest = new MockHttpServletRequest(null, "/path");
		MockHttpServletResponse mockResponse = new MockHttpServletResponse();
		FilterChain mockFilterChain = mock(FilterChain.class);

		assertThatExceptionOfType(AuthenticationCredentialsNotFoundException.class)
				.isThrownBy(() -> filter.doFilter(mockRequest, mockResponse, mockFilterChain))
				.withMessage("An Authentication object was not found in the SecurityContext");

		verifyNoInteractions(mockFilterChain);
	}

	@Test
	public void getAuthorizationManager() {
		AuthorizationManager<HttpServletRequest> authorizationManager = mock(AuthorizationManager.class);
		AuthorizationFilter authorizationFilter = new AuthorizationFilter(authorizationManager);
		assertThat(authorizationFilter.getAuthorizationManager()).isSameAs(authorizationManager);
	}

	@Test
	public void configureWhenAuthorizationEventPublisherIsNullThenIllegalArgument() {
		AuthorizationManager<HttpServletRequest> authorizationManager = mock(AuthorizationManager.class);
		AuthorizationFilter authorizationFilter = new AuthorizationFilter(authorizationManager);
		assertThatIllegalArgumentException().isThrownBy(() -> authorizationFilter.setAuthorizationEventPublisher(null))
				.withMessage("eventPublisher cannot be null");
	}

	@Test
	public void doFilterWhenAuthorizationEventPublisherThenUses() throws Exception {
		AuthorizationFilter authorizationFilter = new AuthorizationFilter(
				AuthenticatedAuthorizationManager.authenticated());
		MockHttpServletRequest mockRequest = new MockHttpServletRequest(null, "/path");
		MockHttpServletResponse mockResponse = new MockHttpServletResponse();
		FilterChain mockFilterChain = mock(FilterChain.class);

		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		SecurityContextHolder.setContext(securityContext);

		AuthorizationEventPublisher eventPublisher = mock(AuthorizationEventPublisher.class);
		authorizationFilter.setAuthorizationEventPublisher(eventPublisher);
		authorizationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);
		verify(eventPublisher).publishAuthorizationEvent(any(Supplier.class), any(HttpServletRequest.class),
				any(AuthorizationDecision.class));
	}

	@Test
	public void doFilterWhenErrorThenDoFilter() throws Exception {
		AuthorizationManager<HttpServletRequest> authorizationManager = mock(AuthorizationManager.class);
		AuthorizationFilter authorizationFilter = new AuthorizationFilter(authorizationManager);
		MockHttpServletRequest mockRequest = new MockHttpServletRequest(null, "/path");
		mockRequest.setDispatcherType(DispatcherType.ERROR);
		mockRequest.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error");
		MockHttpServletResponse mockResponse = new MockHttpServletResponse();
		FilterChain mockFilterChain = mock(FilterChain.class);

		authorizationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);
		verify(authorizationManager).check(any(Supplier.class), eq(mockRequest));
	}

	@Test
	public void doFilterWhenErrorAndShouldFilterAllDispatcherTypesFalseThenDoNotFilter() throws Exception {
		AuthorizationManager<HttpServletRequest> authorizationManager = mock(AuthorizationManager.class);
		AuthorizationFilter authorizationFilter = new AuthorizationFilter(authorizationManager);
		authorizationFilter.setShouldFilterAllDispatcherTypes(false);
		MockHttpServletRequest mockRequest = new MockHttpServletRequest(null, "/path");
		mockRequest.setDispatcherType(DispatcherType.ERROR);
		mockRequest.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error");
		MockHttpServletResponse mockResponse = new MockHttpServletResponse();
		FilterChain mockFilterChain = mock(FilterChain.class);

		authorizationFilter.doFilter(mockRequest, mockResponse, mockFilterChain);
		verifyNoInteractions(authorizationManager);
	}

	@Test
	public void doFilterNestedErrorDispatchWhenAuthorizationManagerThenUses() throws Exception {
		AuthorizationManager<HttpServletRequest> authorizationManager = mock(AuthorizationManager.class);
		AuthorizationFilter authorizationFilter = new AuthorizationFilter(authorizationManager);
		authorizationFilter.setShouldFilterAllDispatcherTypes(true);
		MockHttpServletRequest mockRequest = new MockHttpServletRequest(null, "/path");
		mockRequest.setDispatcherType(DispatcherType.ERROR);
		mockRequest.setAttribute(WebUtils.ERROR_REQUEST_URI_ATTRIBUTE, "/error");
		MockHttpServletResponse mockResponse = new MockHttpServletResponse();
		FilterChain mockFilterChain = mock(FilterChain.class);

		authorizationFilter.doFilterNestedErrorDispatch(mockRequest, mockResponse, mockFilterChain);
		verify(authorizationManager).check(any(Supplier.class), any(HttpServletRequest.class));
	}

	@Test
	public void doFilterNestedErrorDispatchWhenAuthorizationEventPublisherThenUses() throws Exception {
		AuthorizationFilter authorizationFilter = new AuthorizationFilter(
				AuthenticatedAuthorizationManager.authenticated());
		MockHttpServletRequest mockRequest = new MockHttpServletRequest(null, "/path");
		MockHttpServletResponse mockResponse = new MockHttpServletResponse();
		FilterChain mockFilterChain = mock(FilterChain.class);

		SecurityContext securityContext = new SecurityContextImpl();
		securityContext.setAuthentication(new TestingAuthenticationToken("user", "password", "ROLE_USER"));
		SecurityContextHolder.setContext(securityContext);

		AuthorizationEventPublisher eventPublisher = mock(AuthorizationEventPublisher.class);
		authorizationFilter.setAuthorizationEventPublisher(eventPublisher);
		authorizationFilter.doFilterNestedErrorDispatch(mockRequest, mockResponse, mockFilterChain);
		verify(eventPublisher).publishAuthorizationEvent(any(Supplier.class), any(HttpServletRequest.class),
				any(AuthorizationDecision.class));
	}

}
