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

package org.springframework.security.config.method;

import org.junit.After;
import org.junit.Test;

import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.config.util.InMemoryXmlApplicationContext;
import org.springframework.security.core.context.SecurityContextHolder;

import static org.assertj.core.api.Assertions.assertThatExceptionOfType;

/**
 * @author Rob Winch
 *
 */
public class Sec2196Tests {

	private ConfigurableApplicationContext context;

	@Test
	public void genericMethodsProtected() {
		loadContext("<global-method-security secured-annotations=\"enabled\" pre-post-annotations=\"enabled\"/>"
				+ "<b:bean class='" + Service.class.getName() + "'/>");
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken("test", "pass", "ROLE_USER"));
		Service service = this.context.getBean(Service.class);
		assertThatExceptionOfType(AccessDeniedException.class).isThrownBy(() -> service.save(new User()));
	}

	@Test
	public void genericMethodsAllowed() {
		loadContext("<global-method-security secured-annotations=\"enabled\" pre-post-annotations=\"enabled\"/>"
				+ "<b:bean class='" + Service.class.getName() + "'/>");
		SecurityContextHolder.getContext()
				.setAuthentication(new TestingAuthenticationToken("test", "pass", "saveUsers"));
		Service service = this.context.getBean(Service.class);
		service.save(new User());
	}

	private void loadContext(String context) {
		this.context = new InMemoryXmlApplicationContext(context);
	}

	@After
	public void closeAppContext() {
		if (this.context != null) {
			this.context.close();
			this.context = null;
		}
		SecurityContextHolder.clearContext();
	}

	public static class Service {

		@PreAuthorize("hasAuthority('saveUsers')")
		public <T extends User> T save(T dto) {
			return dto;
		}

	}

	static class User {

	}

}
