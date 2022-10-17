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

}
