/*
 * Copyright 2002-2015 the original author or authors.
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
package org.springframework.security.web.authentication;

import java.util.LinkedHashMap;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.core.AuthenticationException;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyZeroInteractions;

/**
 * Test class for
 * {@link org.springframework.security.web.authentication.DelegatingAuthenticationFailureHandler}
 *
 * @author Kazuki shimizu
 * @since 4.0
 */
@RunWith(MockitoJUnitRunner.class)
public class DelegatingAuthenticationFailureHandlerTests {

	@Rule
	public ExpectedException thrown = ExpectedException.none();

	@Mock
	private AuthenticationFailureHandler handler1;

	@Mock
	private AuthenticationFailureHandler handler2;

	@Mock
	private AuthenticationFailureHandler defaultHandler;

	@Mock
	private HttpServletRequest request;

	@Mock
	private HttpServletResponse response;

	private LinkedHashMap<Class<? extends AuthenticationException>, AuthenticationFailureHandler> handlers;

	private DelegatingAuthenticationFailureHandler handler;

	@Before
	public void setup() {
		handlers = new LinkedHashMap<>();
	}

	@Test
	public void handleByDefaultHandler() throws Exception {
		handlers.put(BadCredentialsException.class, handler1);
		handler = new DelegatingAuthenticationFailureHandler(handlers, defaultHandler);

		AuthenticationException exception = new AccountExpiredException("");
		handler.onAuthenticationFailure(request, response, exception);

		verifyZeroInteractions(handler1, handler2);
		verify(defaultHandler).onAuthenticationFailure(request, response, exception);
	}

	@Test
	public void handleByMappedHandlerWithSameType() throws Exception {
		handlers.put(BadCredentialsException.class, handler1); // same type
		handlers.put(AccountStatusException.class, handler2);
		handler = new DelegatingAuthenticationFailureHandler(handlers, defaultHandler);

		AuthenticationException exception = new BadCredentialsException("");
		handler.onAuthenticationFailure(request, response, exception);

		verifyZeroInteractions(handler2, defaultHandler);
		verify(handler1).onAuthenticationFailure(request, response, exception);
	}

	@Test
	public void handleByMappedHandlerWithSuperType() throws Exception {
		handlers.put(BadCredentialsException.class, handler1);
		handlers.put(AccountStatusException.class, handler2); // super type of
																// CredentialsExpiredException
		handler = new DelegatingAuthenticationFailureHandler(handlers, defaultHandler);

		AuthenticationException exception = new CredentialsExpiredException("");
		handler.onAuthenticationFailure(request, response, exception);

		verifyZeroInteractions(handler1, defaultHandler);
		verify(handler2).onAuthenticationFailure(request, response, exception);
	}

	@Test
	public void handlersIsNull() {

		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("handlers cannot be null or empty");

		new DelegatingAuthenticationFailureHandler(null, defaultHandler);

	}

	@Test
	public void handlersIsEmpty() {

		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("handlers cannot be null or empty");

		new DelegatingAuthenticationFailureHandler(handlers, defaultHandler);

	}

	@Test
	public void defaultHandlerIsNull() {

		thrown.expect(IllegalArgumentException.class);
		thrown.expectMessage("defaultHandler cannot be null");

		handlers.put(BadCredentialsException.class, handler1);
		new DelegatingAuthenticationFailureHandler(handlers, null);

	}

}
