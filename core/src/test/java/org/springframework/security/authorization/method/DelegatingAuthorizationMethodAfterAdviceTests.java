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

import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Supplier;

import org.junit.Test;

import org.springframework.aop.MethodMatcher;
import org.springframework.aop.Pointcut;
import org.springframework.aop.support.StaticMethodMatcherPointcut;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link DelegatingAuthorizationMethodAfterAdvice}.
 *
 * @author Evgeniy Cheban
 */
public class DelegatingAuthorizationMethodAfterAdviceTests {

	@Test
	public void methodMatcherWhenNoneMatchesThenNotMatches() throws Exception {
		List<AuthorizationMethodAfterAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationMethodAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object after(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject;
			}

			@Override
			public Pointcut getPointcut() {
				return new StaticMethodMatcherPointcut() {
					@Override
					public boolean matches(Method method, Class<?> targetClass) {
						return false;
					}
				};
			}
		});
		delegates.add(new AuthorizationMethodAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object after(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject;
			}

			@Override
			public Pointcut getPointcut() {
				return new StaticMethodMatcherPointcut() {
					@Override
					public boolean matches(Method method, Class<?> targetClass) {
						return false;
					}
				};
			}
		});
		DelegatingAuthorizationMethodAfterAdvice advice = new DelegatingAuthorizationMethodAfterAdvice(delegates);
		MethodMatcher methodMatcher = advice.getPointcut().getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isFalse();
	}

	@Test
	public void methodMatcherWhenAnyMatchesThenMatches() throws Exception {
		List<AuthorizationMethodAfterAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationMethodAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object after(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject;
			}

			@Override
			public Pointcut getPointcut() {
				return new StaticMethodMatcherPointcut() {
					@Override
					public boolean matches(Method method, Class<?> targetClass) {
						return false;
					}
				};
			}
		});
		delegates.add(new AuthorizationMethodAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object after(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject;
			}

			@Override
			public Pointcut getPointcut() {
				return Pointcut.TRUE;
			}
		});
		DelegatingAuthorizationMethodAfterAdvice advice = new DelegatingAuthorizationMethodAfterAdvice(delegates);
		MethodMatcher methodMatcher = advice.getPointcut().getMethodMatcher();
		assertThat(methodMatcher.matches(TestClass.class.getMethod("doSomething"), TestClass.class)).isTrue();
	}

	@Test
	public void checkWhenDelegatingAdviceModifiesReturnedObjectThenModifiedReturnedObject() throws Exception {
		List<AuthorizationMethodAfterAdvice<MethodAuthorizationContext>> delegates = new ArrayList<>();
		delegates.add(new AuthorizationMethodAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object after(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject + "b";
			}

			@Override
			public Pointcut getPointcut() {
				return Pointcut.TRUE;
			}
		});
		delegates.add(new AuthorizationMethodAfterAdvice<MethodAuthorizationContext>() {
			@Override
			public Object after(Supplier<Authentication> authentication, MethodAuthorizationContext object,
					Object returnedObject) {
				return returnedObject + "c";
			}

			@Override
			public Pointcut getPointcut() {
				return Pointcut.TRUE;
			}
		});
		MockMethodInvocation mockMethodInvocation = new MockMethodInvocation(new TestClass(), TestClass.class,
				"doSomething");
		MethodAuthorizationContext methodAuthorizationContext = new MethodAuthorizationContext(mockMethodInvocation,
				TestClass.class);
		DelegatingAuthorizationMethodAfterAdvice advice = new DelegatingAuthorizationMethodAfterAdvice(delegates);
		Object result = advice.after(TestAuthentication::authenticatedUser, methodAuthorizationContext, "a");
		assertThat(result).isEqualTo("abc");
	}

	public static class TestClass {

		public String doSomething() {
			return null;
		}

	}

}
