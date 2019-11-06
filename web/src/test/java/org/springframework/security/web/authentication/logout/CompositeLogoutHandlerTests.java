/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.authentication.logout;

import java.util.Arrays;
import java.util.List;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.mockito.InOrder;

import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

/**
 * @author Eddú Meléndez
 * @author Rob Winch
 * @since 4.2.0
 */
public class CompositeLogoutHandlerTests {

	@Rule
	public ExpectedException exception = ExpectedException.none();

	@Test
	public void buildEmptyCompositeLogoutHandlerThrowsException() {
		this.exception.expect(IllegalArgumentException.class);
		this.exception.expectMessage("LogoutHandlers are required");
		new CompositeLogoutHandler();
	}

	@Test
	public void callLogoutHandlersSuccessfullyWithArray() {
		LogoutHandler securityContextLogoutHandler = mock(SecurityContextLogoutHandler.class);
		LogoutHandler csrfLogoutHandler = mock(SecurityContextLogoutHandler.class);

		LogoutHandler handler = new CompositeLogoutHandler(securityContextLogoutHandler, csrfLogoutHandler);

		handler.logout(mock(HttpServletRequest.class), mock(HttpServletResponse.class), mock(Authentication.class));

		verify(securityContextLogoutHandler, times(1)).logout(any(HttpServletRequest.class), any(HttpServletResponse.class), any(Authentication.class));
		verify(csrfLogoutHandler, times(1)).logout(any(HttpServletRequest.class), any(HttpServletResponse.class), any(Authentication.class));
	}

	@Test
	public void callLogoutHandlersSuccessfully() {
		LogoutHandler securityContextLogoutHandler = mock(SecurityContextLogoutHandler.class);
		LogoutHandler csrfLogoutHandler = mock(SecurityContextLogoutHandler.class);

		List<LogoutHandler> logoutHandlers = Arrays.asList(securityContextLogoutHandler, csrfLogoutHandler);
		LogoutHandler handler = new CompositeLogoutHandler(logoutHandlers);

		handler.logout(mock(HttpServletRequest.class), mock(HttpServletResponse.class), mock(Authentication.class));

		verify(securityContextLogoutHandler, times(1)).logout(any(HttpServletRequest.class), any(HttpServletResponse.class), any(Authentication.class));
		verify(csrfLogoutHandler, times(1)).logout(any(HttpServletRequest.class), any(HttpServletResponse.class), any(Authentication.class));
	}

	@Test
	public void callLogoutHandlersThrowException() {
		LogoutHandler firstLogoutHandler = mock(LogoutHandler.class);
		LogoutHandler secondLogoutHandler = mock(LogoutHandler.class);

		doThrow(new IllegalArgumentException()).when(firstLogoutHandler).logout(any(HttpServletRequest.class), any(HttpServletResponse.class), any(Authentication.class));

		List<LogoutHandler> logoutHandlers = Arrays.asList(firstLogoutHandler, secondLogoutHandler);
		LogoutHandler handler = new CompositeLogoutHandler(logoutHandlers);

		try {
			handler.logout(mock(HttpServletRequest.class), mock(HttpServletResponse.class), mock(Authentication.class));
			fail("Expected Exception");
		} catch (IllegalArgumentException success) {
		}

		InOrder logoutHandlersInOrder = inOrder(firstLogoutHandler, secondLogoutHandler);

		logoutHandlersInOrder.verify(firstLogoutHandler, times(1)).logout(any(HttpServletRequest.class), any(HttpServletResponse.class), any(Authentication.class));
		logoutHandlersInOrder.verify(secondLogoutHandler, never()).logout(any(HttpServletRequest.class), any(HttpServletResponse.class), any(Authentication.class));
	}

}
