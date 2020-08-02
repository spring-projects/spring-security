/*
 * Copyright 2002-2013 the original author or authors.
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

package org.springframework.security.web.authentication.session;

import java.util.Arrays;
import java.util.Collections;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.fail;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Rob Winch
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class CompositeSessionAuthenticationStrategyTests {

	@Mock
	private SessionAuthenticationStrategy strategy1;

	@Mock
	private SessionAuthenticationStrategy strategy2;

	@Mock
	private Authentication authentication;

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	@Test(expected = IllegalArgumentException.class)
	public void constructorNullDelegates() {
		new CompositeSessionAuthenticationStrategy(null);
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorEmptyDelegates() {
		new CompositeSessionAuthenticationStrategy(Collections.<SessionAuthenticationStrategy>emptyList());
	}

	@Test(expected = IllegalArgumentException.class)
	public void constructorDelegatesContainNull() {
		new CompositeSessionAuthenticationStrategy(Collections.<SessionAuthenticationStrategy>singletonList(null));
	}

	@Test
	public void delegatesToAll() {
		CompositeSessionAuthenticationStrategy strategy = new CompositeSessionAuthenticationStrategy(
				Arrays.asList(this.strategy1, this.strategy2));
		strategy.onAuthentication(this.authentication, this.request, this.response);
		verify(this.strategy1).onAuthentication(this.authentication, this.request, this.response);
		verify(this.strategy2).onAuthentication(this.authentication, this.request, this.response);
	}

	@Test
	public void delegateShortCircuits() {
		willThrow(new SessionAuthenticationException("oops")).given(this.strategy1)
				.onAuthentication(this.authentication, this.request, this.response);
		CompositeSessionAuthenticationStrategy strategy = new CompositeSessionAuthenticationStrategy(
				Arrays.asList(this.strategy1, this.strategy2));
		try {
			strategy.onAuthentication(this.authentication, this.request, this.response);
			fail("Expected Exception");
		}
		catch (SessionAuthenticationException success) {
		}
		verify(this.strategy1).onAuthentication(this.authentication, this.request, this.response);
		verify(this.strategy2, times(0)).onAuthentication(this.authentication, this.request, this.response);
	}

}
