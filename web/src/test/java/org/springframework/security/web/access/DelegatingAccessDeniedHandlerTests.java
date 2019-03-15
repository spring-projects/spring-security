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
package org.springframework.security.web.access;

import static org.mockito.Matchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.util.LinkedHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

@RunWith(MockitoJUnitRunner.class)
public class DelegatingAccessDeniedHandlerTests {
	@Mock
	private AccessDeniedHandler handler1;
	@Mock
	private AccessDeniedHandler handler2;
	@Mock
	private AccessDeniedHandler handler3;
	@Mock
	private HttpServletRequest request;
	@Mock
	private HttpServletResponse response;

	private LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler> handlers;

	private DelegatingAccessDeniedHandler handler;

	@Before
	public void setup() {
		handlers = new LinkedHashMap<Class<? extends AccessDeniedException>, AccessDeniedHandler>();
	}

	@Test
	public void moreSpecificDoesNotInvokeLessSpecific() throws Exception {
		handlers.put(CsrfException.class, handler1);
		handler = new DelegatingAccessDeniedHandler(handlers, handler3);

		AccessDeniedException accessDeniedException = new AccessDeniedException("");
		handler.handle(request, response, accessDeniedException);

		verify(handler1, never()).handle(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AccessDeniedException.class));
		verify(handler3).handle(request, response, accessDeniedException);
	}

	@Test
	public void matchesDoesNotInvokeDefault() throws Exception {
		handlers.put(InvalidCsrfTokenException.class, handler1);
		handlers.put(MissingCsrfTokenException.class, handler2);
		handler = new DelegatingAccessDeniedHandler(handlers, handler3);

		AccessDeniedException accessDeniedException = new MissingCsrfTokenException("123");
		handler.handle(request, response, accessDeniedException);

		verify(handler1, never()).handle(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AccessDeniedException.class));
		verify(handler2).handle(request, response, accessDeniedException);
		verify(handler3, never()).handle(any(HttpServletRequest.class),
				any(HttpServletResponse.class), any(AccessDeniedException.class));
	}
}
