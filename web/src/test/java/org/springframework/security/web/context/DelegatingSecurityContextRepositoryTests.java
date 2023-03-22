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

package org.springframework.security.web.context;

import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * Tests for {@link DelegatingSecurityContextRepository}.
 *
 * @author Steve Riesenberg
 * @since 5.8
 */
public class DelegatingSecurityContextRepositoryTests {

	private MockHttpServletRequest request;

	private MockHttpServletResponse response;

	private SecurityContextHolderStrategy strategy;

	private SecurityContext securityContext;

	@BeforeEach
	public void setUp() {
		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
		this.strategy = mock(SecurityContextHolderStrategy.class);
		this.securityContext = mock(SecurityContext.class);
	}

	@ParameterizedTest
	@CsvSource({ "0,false", "1,false", "2,false", "-1,true" })
	public void loadDeferredContextWhenIsGeneratedThenReturnsSecurityContext(int expectedIndex, boolean isGenerated) {
		SecurityContext actualSecurityContext = new SecurityContextImpl(
				new TestingAuthenticationToken("user", "password"));
		SecurityContext emptySecurityContext = new SecurityContextImpl();
		given(this.strategy.createEmptyContext()).willReturn(emptySecurityContext);
		List<SecurityContextRepository> delegates = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			SecurityContext context = (i == expectedIndex) ? actualSecurityContext : null;
			SecurityContextRepository repository = mock(SecurityContextRepository.class);
			SupplierDeferredSecurityContext supplier = new SupplierDeferredSecurityContext(() -> context,
					this.strategy);
			given(repository.loadDeferredContext(this.request)).willReturn(supplier);
			delegates.add(repository);
		}

		DelegatingSecurityContextRepository repository = new DelegatingSecurityContextRepository(delegates);
		DeferredSecurityContext deferredSecurityContext = repository.loadDeferredContext(this.request);
		SecurityContext expectedSecurityContext = (isGenerated) ? emptySecurityContext : actualSecurityContext;
		assertThat(deferredSecurityContext.get()).isEqualTo(expectedSecurityContext);
		assertThat(deferredSecurityContext.isGenerated()).isEqualTo(isGenerated);

		for (SecurityContextRepository delegate : delegates) {
			verify(delegate).loadDeferredContext(this.request);
			verifyNoMoreInteractions(delegate);
		}
	}

	@Test
	public void saveContextAlwaysCallsDelegates() {
		List<SecurityContextRepository> delegates = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			SecurityContextRepository repository = mock(SecurityContextRepository.class);
			delegates.add(repository);
		}

		DelegatingSecurityContextRepository repository = new DelegatingSecurityContextRepository(delegates);
		repository.saveContext(this.securityContext, this.request, this.response);
		for (SecurityContextRepository delegate : delegates) {
			verify(delegate).saveContext(this.securityContext, this.request, this.response);
			verifyNoMoreInteractions(delegate);
		}
	}

	@Test
	public void containsContextWhenAllDelegatesReturnFalseThenReturnsFalse() {
		List<SecurityContextRepository> delegates = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			SecurityContextRepository repository = mock(SecurityContextRepository.class);
			given(repository.containsContext(this.request)).willReturn(false);
			delegates.add(repository);
		}

		DelegatingSecurityContextRepository repository = new DelegatingSecurityContextRepository(delegates);
		assertThat(repository.containsContext(this.request)).isFalse();
		for (SecurityContextRepository delegate : delegates) {
			verify(delegate).containsContext(this.request);
			verifyNoMoreInteractions(delegate);
		}
	}

	@Test
	public void containsContextWhenFirstDelegatesReturnTrueThenReturnsTrue() {
		List<SecurityContextRepository> delegates = new ArrayList<>();
		for (int i = 0; i < 3; i++) {
			SecurityContextRepository repository = mock(SecurityContextRepository.class);
			given(repository.containsContext(this.request)).willReturn(true);
			delegates.add(repository);
		}

		DelegatingSecurityContextRepository repository = new DelegatingSecurityContextRepository(delegates);
		assertThat(repository.containsContext(this.request)).isTrue();
		verify(delegates.get(0)).containsContext(this.request);
		verifyNoInteractions(delegates.get(1));
		verifyNoInteractions(delegates.get(2));
	}

	// gh-12314
	@Test
	public void loadContextWhenSecondDelegateReturnsThenContextFromSecondDelegate() {
		SecurityContextRepository delegate1 = mock(SecurityContextRepository.class);
		SecurityContextRepository delegate2 = mock(SecurityContextRepository.class);
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(this.request, this.response);
		SecurityContext securityContext1 = mock(SecurityContext.class);
		SecurityContext securityContext2 = mock(SecurityContext.class);

		given(delegate1.loadContext(holder)).willReturn(securityContext1);
		given(delegate1.containsContext(holder.getRequest())).willReturn(false);
		given(delegate2.loadContext(holder)).willReturn(securityContext2);
		given(delegate2.containsContext(holder.getRequest())).willReturn(true);

		DelegatingSecurityContextRepository repository = new DelegatingSecurityContextRepository(delegate1, delegate2);
		SecurityContext returnedSecurityContext = repository.loadContext(holder);

		assertThat(returnedSecurityContext).isSameAs(securityContext2);
	}

	// gh-12314
	@Test
	public void loadContextWhenBothDelegateReturnsThenContextFromSecondDelegate() {
		SecurityContextRepository delegate1 = mock(SecurityContextRepository.class);
		SecurityContextRepository delegate2 = mock(SecurityContextRepository.class);
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(this.request, this.response);
		SecurityContext securityContext1 = mock(SecurityContext.class);
		SecurityContext securityContext2 = mock(SecurityContext.class);

		given(delegate1.loadContext(holder)).willReturn(securityContext1);
		given(delegate1.containsContext(holder.getRequest())).willReturn(true);
		given(delegate2.loadContext(holder)).willReturn(securityContext2);
		given(delegate2.containsContext(holder.getRequest())).willReturn(true);

		DelegatingSecurityContextRepository repository = new DelegatingSecurityContextRepository(delegate1, delegate2);
		SecurityContext returnedSecurityContext = repository.loadContext(holder);

		assertThat(returnedSecurityContext).isSameAs(securityContext2);
	}

	// gh-12314
	@Test
	public void loadContextWhenFirstDelegateReturnsThenContextFromFirstDelegate() {
		SecurityContextRepository delegate1 = mock(SecurityContextRepository.class);
		SecurityContextRepository delegate2 = mock(SecurityContextRepository.class);
		HttpRequestResponseHolder holder = new HttpRequestResponseHolder(this.request, this.response);
		SecurityContext securityContext1 = mock(SecurityContext.class);
		SecurityContext securityContext2 = mock(SecurityContext.class);

		given(delegate1.loadContext(holder)).willReturn(securityContext1);
		given(delegate1.containsContext(holder.getRequest())).willReturn(true);
		given(delegate2.loadContext(holder)).willReturn(securityContext2);
		given(delegate2.containsContext(holder.getRequest())).willReturn(false);

		DelegatingSecurityContextRepository repository = new DelegatingSecurityContextRepository(delegate1, delegate2);
		SecurityContext returnedSecurityContext = repository.loadContext(holder);

		assertThat(returnedSecurityContext).isSameAs(securityContext1);
	}

}
