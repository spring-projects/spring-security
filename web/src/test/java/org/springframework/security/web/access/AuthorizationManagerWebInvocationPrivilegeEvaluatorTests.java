/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.access;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockServletContext;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.web.access.AuthorizationManagerWebInvocationPrivilegeEvaluator.HttpServletRequestTransformer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class AuthorizationManagerWebInvocationPrivilegeEvaluatorTests {

	@InjectMocks
	private AuthorizationManagerWebInvocationPrivilegeEvaluator privilegeEvaluator;

	@Mock
	private AuthorizationManager<HttpServletRequest> authorizationManager;

	@Mock
	private HttpServletRequestTransformer requestTransformer;

	@Test
	void constructorWhenAuthorizationManagerNullThenIllegalArgument() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> new AuthorizationManagerWebInvocationPrivilegeEvaluator(null))
			.withMessage("authorizationManager cannot be null");
	}

	@Test
	void isAllowedWhenAuthorizationManagerAllowsThenAllowedTrue() {
		given(this.authorizationManager.check(any(), any())).willReturn(new AuthorizationDecision(true));
		given(this.authorizationManager.authorize(any(), any())).willCallRealMethod();
		boolean allowed = this.privilegeEvaluator.isAllowed("/test", TestAuthentication.authenticatedUser());
		assertThat(allowed).isTrue();
		verify(this.authorizationManager).check(any(), any());
	}

	@Test
	void isAllowedWhenAuthorizationManagerDeniesAllowedFalse() {
		given(this.authorizationManager.check(any(), any())).willReturn(new AuthorizationDecision(false));
		given(this.authorizationManager.authorize(any(), any())).willCallRealMethod();
		boolean allowed = this.privilegeEvaluator.isAllowed("/test", TestAuthentication.authenticatedUser());
		assertThat(allowed).isFalse();
	}

	@Test
	void isAllowedWhenAuthorizationManagerAbstainsThenAllowedTrue() {
		given(this.authorizationManager.check(any(), any())).willReturn(null);
		given(this.authorizationManager.authorize(any(), any())).willCallRealMethod();
		boolean allowed = this.privilegeEvaluator.isAllowed("/test", TestAuthentication.authenticatedUser());
		assertThat(allowed).isTrue();
	}

	@Test
	void isAllowedWhenServletContextExistsThenFilterInvocationHasServletContext() {
		ServletContext servletContext = new MockServletContext();
		given(this.authorizationManager.authorize(any(), any())).willCallRealMethod();
		this.privilegeEvaluator.setServletContext(servletContext);
		this.privilegeEvaluator.isAllowed("/test", TestAuthentication.authenticatedUser());
		ArgumentCaptor<HttpServletRequest> captor = ArgumentCaptor.forClass(HttpServletRequest.class);
		verify(this.authorizationManager).check(any(), captor.capture());
		assertThat(captor.getValue().getServletContext()).isSameAs(servletContext);
	}

	@Test
	void setRequestTransformerWhenNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.privilegeEvaluator.setRequestTransformer(null));
	}

	@Test
	void isAllowedWhenRequestTransformerThenUsesRequestTransformerResult() {
		HttpServletRequest request = new MockHttpServletRequest();
		given(this.requestTransformer.transform(any())).willReturn(request);
		given(this.authorizationManager.authorize(any(), any())).willCallRealMethod();
		this.privilegeEvaluator.setRequestTransformer(this.requestTransformer);

		this.privilegeEvaluator.isAllowed("/test", TestAuthentication.authenticatedUser());

		verify(this.authorizationManager).check(any(), eq(request));
	}

}
