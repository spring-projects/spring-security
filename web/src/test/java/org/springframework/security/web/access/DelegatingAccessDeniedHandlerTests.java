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

import java.util.LinkedHashMap;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
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

	@BeforeEach
	public void setup() {
		this.handlers = new LinkedHashMap<>();
	}

	@Test
	public void moreSpecificDoesNotInvokeLessSpecific() throws Exception {
		this.handlers.put(CsrfException.class, this.handler1);
		this.handler = new DelegatingAccessDeniedHandler(this.handlers, this.handler3);
		AccessDeniedException accessDeniedException = new AccessDeniedException("");
		this.handler.handle(this.request, this.response, accessDeniedException);
		verify(this.handler1, never()).handle(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(AccessDeniedException.class));
		verify(this.handler3).handle(this.request, this.response, accessDeniedException);
	}

	@Test
	public void matchesDoesNotInvokeDefault() throws Exception {
		this.handlers.put(InvalidCsrfTokenException.class, this.handler1);
		this.handlers.put(MissingCsrfTokenException.class, this.handler2);
		this.handler = new DelegatingAccessDeniedHandler(this.handlers, this.handler3);
		AccessDeniedException accessDeniedException = new MissingCsrfTokenException("123");
		this.handler.handle(this.request, this.response, accessDeniedException);
		verify(this.handler1, never()).handle(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(AccessDeniedException.class));
		verify(this.handler2).handle(this.request, this.response, accessDeniedException);
		verify(this.handler3, never()).handle(any(HttpServletRequest.class), any(HttpServletResponse.class),
				any(AccessDeniedException.class));
	}

}
