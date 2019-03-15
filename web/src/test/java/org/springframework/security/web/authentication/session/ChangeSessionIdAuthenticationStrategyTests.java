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

import static org.mockito.Matchers.*;
import static org.powermock.api.mockito.PowerMockito.*;

import java.lang.reflect.Method;

import javax.servlet.http.HttpServletRequest;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.util.ReflectionUtils;

/**
 * @author Rob Winch
 *
 */
@RunWith(PowerMockRunner.class)
@PrepareForTest({ ReflectionUtils.class, Method.class })
public class ChangeSessionIdAuthenticationStrategyTests {
	@Mock
	private Method method;

	@Test(expected = IllegalStateException.class)
	public void constructChangeIdMethodNotFound() {
		spy(ReflectionUtils.class);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.getSession();
		when(ReflectionUtils.findMethod(HttpServletRequest.class, "changeSessionId"))
				.thenReturn(null);

		new ChangeSessionIdAuthenticationStrategy();
	}

	@Test
	public void applySessionFixation() throws Exception {
		spy(ReflectionUtils.class);
		Method method = mock(Method.class);
		MockHttpServletRequest request = new MockHttpServletRequest();
		request.getSession();
		when(ReflectionUtils.findMethod(HttpServletRequest.class, "changeSessionId"))
				.thenReturn(method);

		new ChangeSessionIdAuthenticationStrategy().applySessionFixation(request);

		verifyStatic(ReflectionUtils.class);
		ReflectionUtils.invokeMethod(same(method), eq(request));
	}

}
