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

import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;
import org.junit.Test;

import org.springframework.aop.MethodMatcher;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.method.AuthorizationManagerMethodAfterAdvice;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * Tests for {@link AuthorizationManagerMethodAfterAdvice}.
 *
 * @author Evgeniy Cheban
 */
public class AuthorizationManagerMethodAfterAdviceTests {

	@Test
	public void instantiateWhenMethodMatcherNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AuthorizationManagerMethodAfterAdvice<>(null, mock(AuthorizationManager.class)))
				.withMessage("methodMatcher cannot be null");
	}

	@Test
	public void instantiateWhenAuthorizationManagerNullThenException() {
		assertThatIllegalArgumentException()
				.isThrownBy(() -> new AuthorizationManagerMethodAfterAdvice<>(mock(MethodMatcher.class), null))
				.withMessage("authorizationManager cannot be null");
	}

	@Test
	public void beforeWhenMockAuthorizationManagerThenVerifyAndReturnedObject() {
		Supplier<Authentication> authentication = TestAuthentication::authenticatedUser;
		MethodInvocation mockMethodInvocation = mock(MethodInvocation.class);
		Object returnedObject = new Object();
		AuthorizationManager<MethodInvocation> mockAuthorizationManager = mock(AuthorizationManager.class);
		AuthorizationManagerMethodAfterAdvice<MethodInvocation> advice = new AuthorizationManagerMethodAfterAdvice<>(
				mock(MethodMatcher.class), mockAuthorizationManager);
		Object result = advice.after(authentication, mockMethodInvocation, returnedObject);
		assertThat(result).isEqualTo(returnedObject);
		verify(mockAuthorizationManager).verify(authentication, mockMethodInvocation);
	}

}
