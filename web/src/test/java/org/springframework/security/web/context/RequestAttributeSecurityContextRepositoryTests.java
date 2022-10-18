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

import org.junit.jupiter.api.Test;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.core.context.SecurityContextImpl;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoMoreInteractions;

/**
 * @author Rob Winch
 */
class RequestAttributeSecurityContextRepositoryTests {

	private MockHttpServletRequest request = new MockHttpServletRequest();

	private MockHttpServletResponse response = new MockHttpServletResponse();

	private RequestAttributeSecurityContextRepository repository = new RequestAttributeSecurityContextRepository();

	private SecurityContext expectedSecurityContext = new SecurityContextImpl(TestAuthentication.authenticatedUser());

	@Test
	void setSecurityContextHolderStrategyWhenNullThenThrowsIllegalArgumentException() {
		// @formatter:off
		assertThatIllegalArgumentException()
				.isThrownBy(() -> this.repository.setSecurityContextHolderStrategy(null))
				.withMessage("securityContextHolderStrategy cannot be null");
		// @formatter:on
	}

	@Test
	void saveContextAndLoadContextThenFound() {
		this.repository.saveContext(this.expectedSecurityContext, this.request, this.response);
		SecurityContext securityContext = this.repository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response));
		assertThat(securityContext).isEqualTo(this.expectedSecurityContext);
	}

	@Test
	void saveContextWhenLoadContextAndNewRequestThenNotFound() {
		this.repository.saveContext(this.expectedSecurityContext, this.request, this.response);
		SecurityContext securityContext = this.repository.loadContext(
				new HttpRequestResponseHolder(new MockHttpServletRequest(), new MockHttpServletResponse()));
		assertThat(securityContext).isEqualTo(SecurityContextHolder.createEmptyContext());
	}

	@Test
	void containsContextWhenNotSavedThenFalse() {
		assertThat(this.repository.containsContext(this.request)).isFalse();
	}

	@Test
	void containsContextWhenSavedThenTrue() {
		this.repository.saveContext(this.expectedSecurityContext, this.request, this.response);
		assertThat(this.repository.containsContext(this.request)).isTrue();
	}

	@Test
	void loadDeferredContextWhenNotPresentThenEmptyContext() {
		Supplier<SecurityContext> deferredContext = this.repository.loadDeferredContext(this.request);
		assertThat(deferredContext.get()).isEqualTo(SecurityContextHolder.createEmptyContext());
	}

	@Test
	void loadContextWhenNotPresentThenEmptyContext() {
		SecurityContext context = this.repository
				.loadContext(new HttpRequestResponseHolder(this.request, this.response));
		assertThat(context).isEqualTo(SecurityContextHolder.createEmptyContext());
	}

	@Test
	void loadContextWhenCustomSecurityContextHolderStrategySetThenUsed() {
		SecurityContextHolderStrategy securityContextHolderStrategy = mock(SecurityContextHolderStrategy.class);
		given(securityContextHolderStrategy.createEmptyContext()).willReturn(new SecurityContextImpl());
		this.repository.setSecurityContextHolderStrategy(securityContextHolderStrategy);

		Supplier<SecurityContext> deferredContext = this.repository.loadDeferredContext(this.request);
		assertThat(deferredContext.get()).isNotNull();
		verify(securityContextHolderStrategy).createEmptyContext();
		verifyNoMoreInteractions(securityContextHolderStrategy);
	}

}
