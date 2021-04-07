/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization.method;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;

import org.springframework.aop.Pointcut;
import org.springframework.security.authorization.AuthorizationManager;

import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AuthorizationManagerBeforeMethodInterceptor}.
 *
 * @author Evgeniy Cheban
 */
public class AuthorizationManagerBeforeMethodInterceptorTests {

	@Test
	public void instantiateWhenMethodMatcherNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(
						() -> new AuthorizationManagerBeforeMethodInterceptor(null, mock(AuthorizationManager.class)))
				.withMessage("pointcut cannot be null");
	}

	@Test
	public void instantiateWhenAuthorizationManagerNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AuthorizationManagerBeforeMethodInterceptor(mock(Pointcut.class), null))
				.withMessage("authorizationManager cannot be null");
	}

	@Test
	public void beforeWhenMockAuthorizationManagerThenVerify() throws Throwable {
		MethodInvocation mockMethodInvocation = mock(MethodInvocation.class);
		AuthorizationManager<MethodInvocation> mockAuthorizationManager = mock(AuthorizationManager.class);
		AuthorizationManagerBeforeMethodInterceptor advice = new AuthorizationManagerBeforeMethodInterceptor(
				Pointcut.TRUE, mockAuthorizationManager);
		advice.invoke(mockMethodInvocation);
		verify(mockAuthorizationManager).verify(AuthorizationManagerBeforeMethodInterceptor.AUTHENTICATION_SUPPLIER,
				mockMethodInvocation);
	}

}
