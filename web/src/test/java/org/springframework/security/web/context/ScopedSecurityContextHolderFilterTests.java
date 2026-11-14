/*
 * Copyright 2004-present the original author or authors.
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

import java.util.function.Supplier;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.ScopedSecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class ScopedSecurityContextHolderFilterTests {

	private static final String FILTER_APPLIED = ScopedSecurityContextHolderFilter.class.getName() + ".APPLIED";

	@Mock
	private SecurityContextRepository repository;

	@Mock
	private ScopedSecurityContextHolderStrategy strategy;

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	@Captor
	private ArgumentCaptor<HttpServletRequest> requestArg;

	private ScopedSecurityContextHolderFilter filter;

	private SecurityContextHolderStrategy originalStrategy;

	@BeforeEach
	void setup() {
		this.originalStrategy = SecurityContextHolder.getContextHolderStrategy();
		SecurityContextHolder.setContextHolderStrategy(new ScopedSecurityContextHolderStrategy());
		this.filter = new ScopedSecurityContextHolderFilter(this.repository);
	}

	@AfterEach
	void cleanup() {
		SecurityContextHolder.setContextHolderStrategy(this.originalStrategy);
		SecurityContextHolder.clearContext();
	}

	@Test
	void doFilterThenGetSecurityContextHolderOnUnbound() throws Exception {
		Authentication authentication = TestAuthentication.authenticatedUser();
		SecurityContext expectedContext = new SecurityContextImpl(authentication);
		given(this.repository.loadDeferredContext(this.requestArg.capture()))
			.willReturn(new SupplierDeferredSecurityContext(() -> expectedContext, this.strategy));
		FilterChain filterChain = (request, response) -> assertThat(SecurityContextHolder.getContext())
			.isEqualTo(expectedContext);

		this.filter.doFilter(this.request, this.response, filterChain);

		assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> SecurityContextHolder.getContext());
	}

	@Test
	void doFilterThenSetAndGetSecurityContext() throws Exception {
		Authentication authentication = TestAuthentication.authenticatedUser();
		SecurityContext expectedContext = new SecurityContextImpl(authentication);
		given(this.repository.loadDeferredContext(this.requestArg.capture()))
			.willReturn(new SupplierDeferredSecurityContext(() -> expectedContext, this.strategy));
		FilterChain filterChain = (request, response) -> {
		};

		this.filter.setSecurityContextHolderStrategy(this.strategy);
		this.filter.doFilter(this.request, this.response, filterChain);

		ArgumentCaptor<Supplier<SecurityContext>> deferredContextArg = ArgumentCaptor.forClass(Supplier.class);
		verify(this.strategy).setDeferredContext(deferredContextArg.capture());
		assertThat(deferredContextArg.getValue().get()).isEqualTo(expectedContext);
		assertThatExceptionOfType(IllegalStateException.class).isThrownBy(() -> SecurityContextHolder.getContext());
	}

	@Test
	void doFilterWhenFilterAppliedThenDoNothing() throws Exception {
		given(this.request.getAttribute(FILTER_APPLIED)).willReturn(true);
		this.filter.doFilter(this.request, this.response, new MockFilterChain());
		verify(this.request, times(1)).getAttribute(FILTER_APPLIED);
		verifyNoInteractions(this.repository, this.response);
	}

	@Test
	void doFilterWhenNotAppliedThenSetsAndRemovesAttribute() throws Exception {
		given(this.repository.loadDeferredContext(this.requestArg.capture()))
			.willReturn(new SupplierDeferredSecurityContext(SecurityContextHolder::createEmptyContext, this.strategy));

		this.filter.doFilter(this.request, this.response, new MockFilterChain());

		InOrder inOrder = inOrder(this.request, this.repository);
		inOrder.verify(this.request).setAttribute(FILTER_APPLIED, true);
		inOrder.verify(this.repository).loadDeferredContext(this.request);
		inOrder.verify(this.request).removeAttribute(FILTER_APPLIED);
	}

	@ParameterizedTest
	@EnumSource(DispatcherType.class)
	void doFilterWhenAnyDispatcherTypeThenFilter(DispatcherType dispatcherType) throws Exception {
		lenient().when(this.request.getDispatcherType()).thenReturn(dispatcherType);
		Authentication authentication = TestAuthentication.authenticatedUser();
		SecurityContext expectedContext = new SecurityContextImpl(authentication);
		given(this.repository.loadDeferredContext(this.requestArg.capture()))
			.willReturn(new SupplierDeferredSecurityContext(() -> expectedContext, this.strategy));
		FilterChain filterChain = (request, response) -> assertThat(SecurityContextHolder.getContext())
			.isEqualTo(expectedContext);

		this.filter.doFilter(this.request, this.response, filterChain);
	}

}
