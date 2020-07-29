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
		this.handlers = new LinkedHashMap<>();
	}

	@Test
	public void handleByDefaultHandler() throws Exception {
		this.handlers.put(BadCredentialsException.class, this.handler1);
		this.handler = new DelegatingAuthenticationFailureHandler(this.handlers, this.defaultHandler);

		AuthenticationException exception = new AccountExpiredException("");
		this.handler.onAuthenticationFailure(this.request, this.response, exception);

		verifyZeroInteractions(this.handler1, this.handler2);
		verify(this.defaultHandler).onAuthenticationFailure(this.request, this.response, exception);
	}

	@Test
	public void handleByMappedHandlerWithSameType() throws Exception {
		this.handlers.put(BadCredentialsException.class, this.handler1); // same type
		this.handlers.put(AccountStatusException.class, this.handler2);
		this.handler = new DelegatingAuthenticationFailureHandler(this.handlers, this.defaultHandler);

		AuthenticationException exception = new BadCredentialsException("");
		this.handler.onAuthenticationFailure(this.request, this.response, exception);

		verifyZeroInteractions(this.handler2, this.defaultHandler);
		verify(this.handler1).onAuthenticationFailure(this.request, this.response, exception);
	}

	@Test
	public void handleByMappedHandlerWithSuperType() throws Exception {
		this.handlers.put(BadCredentialsException.class, this.handler1);
		this.handlers.put(AccountStatusException.class, this.handler2); // super type of
		// CredentialsExpiredException
		this.handler = new DelegatingAuthenticationFailureHandler(this.handlers, this.defaultHandler);

		AuthenticationException exception = new CredentialsExpiredException("");
		this.handler.onAuthenticationFailure(this.request, this.response, exception);

		verifyZeroInteractions(this.handler1, this.defaultHandler);
		verify(this.handler2).onAuthenticationFailure(this.request, this.response, exception);
	}

	@Test
	public void handlersIsNull() {

		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("handlers cannot be null or empty");

		new DelegatingAuthenticationFailureHandler(null, this.defaultHandler);

	}

	@Test
	public void handlersIsEmpty() {

		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("handlers cannot be null or empty");

		new DelegatingAuthenticationFailureHandler(this.handlers, this.defaultHandler);

	}

	@Test
	public void defaultHandlerIsNull() {

		this.thrown.expect(IllegalArgumentException.class);
		this.thrown.expectMessage("defaultHandler cannot be null");

		this.handlers.put(BadCredentialsException.class, this.handler1);
		new DelegatingAuthenticationFailureHandler(this.handlers, null);

	}

}
