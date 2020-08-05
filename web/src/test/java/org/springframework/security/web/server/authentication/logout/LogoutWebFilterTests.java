/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.web.server.authentication.logout;

import java.util.Arrays;
import java.util.Collection;
import java.util.stream.Collectors;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.junit.MockitoJUnitRunner;

import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Eric Deandrea
 * @since 5.1
 */
@RunWith(MockitoJUnitRunner.class)
public class LogoutWebFilterTests {

	@Mock
	private ServerLogoutHandler handler1;

	@Mock
	private ServerLogoutHandler handler2;

	@Mock
	private ServerLogoutHandler handler3;

	private LogoutWebFilter logoutWebFilter = new LogoutWebFilter();

	@Test
	public void defaultLogoutHandler() {
		assertThat(getLogoutHandler()).isNotNull().isExactlyInstanceOf(SecurityContextServerLogoutHandler.class);
	}

	@Test
	public void singleLogoutHandler() {
		this.logoutWebFilter.setLogoutHandler(this.handler1);
		this.logoutWebFilter.setLogoutHandler(this.handler2);

		assertThat(getLogoutHandler()).isNotNull().isInstanceOf(ServerLogoutHandler.class)
				.isNotInstanceOf(SecurityContextServerLogoutHandler.class).extracting(ServerLogoutHandler::getClass)
				.isEqualTo(this.handler2.getClass());
	}

	@Test
	public void multipleLogoutHandlers() {
		this.logoutWebFilter
				.setLogoutHandler(new DelegatingServerLogoutHandler(this.handler1, this.handler2, this.handler3));

		assertThat(getLogoutHandler()).isNotNull().isExactlyInstanceOf(DelegatingServerLogoutHandler.class)
				.extracting(delegatingLogoutHandler -> ((Collection<ServerLogoutHandler>) ReflectionTestUtils
						.getField(delegatingLogoutHandler, DelegatingServerLogoutHandler.class, "delegates")).stream()
								.map(ServerLogoutHandler::getClass).collect(Collectors.toList()))
				.isEqualTo(Arrays.asList(this.handler1.getClass(), this.handler2.getClass(), this.handler3.getClass()));
	}

	private ServerLogoutHandler getLogoutHandler() {
		return (ServerLogoutHandler) ReflectionTestUtils.getField(this.logoutWebFilter, LogoutWebFilter.class,
				"logoutHandler");
	}

}
