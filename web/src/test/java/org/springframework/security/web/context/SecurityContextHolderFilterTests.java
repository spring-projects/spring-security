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

package org.springframework.security.web.context;

import java.util.function.Supplier;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class SecurityContextHolderFilterTests {

	@Mock
	private SecurityContextRepository repository;

	@Mock
	private SecurityContextHolderStrategy strategy;

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	@Captor
	private ArgumentCaptor<HttpServletRequest> requestArg;

	private SecurityContextHolderFilter filter;

	@BeforeEach
	void setup() {
		this.filter = new SecurityContextHolderFilter(this.repository);
	}

	@AfterEach
	void cleanup() {
		SecurityContextHolder.clearContext();
	}

	@Test
	void doFilterThenSetsAndClearsSecurityContextHolder() throws Exception {
		Authentication authentication = TestAuthentication.authenticatedUser();
		SecurityContext expectedContext = new SecurityContextImpl(authentication);
		given(this.repository.loadDeferredContext(this.requestArg.capture()))
				.willReturn(new SupplierDeferredSecurityContext(() -> expectedContext, this.strategy));
		FilterChain filterChain = (request, response) -> assertThat(SecurityContextHolder.getContext())
				.isEqualTo(expectedContext);

		this.filter.doFilter(this.request, this.response, filterChain);

		assertThat(SecurityContextHolder.getContext()).isEqualTo(SecurityContextHolder.createEmptyContext());
	}

	@Test
	void doFilterThenSetsAndClearsSecurityContextHolderStrategy() throws Exception {
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
		verify(this.strategy).clearContext();
	}

	@Test
	void shouldNotFilterErrorDispatchWhenDefault() {
		assertThat(this.filter.shouldNotFilterErrorDispatch()).isFalse();
	}

	@Test
	void shouldNotFilterErrorDispatchWhenOverridden() {
		this.filter.setShouldNotFilterErrorDispatch(true);
		assertThat(this.filter.shouldNotFilterErrorDispatch()).isTrue();
	}

}
