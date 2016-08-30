/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.web.authentication.logout;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.springframework.context.annotation.AnnotationConfigApplicationContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.event.EventListener;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Test cases for the {@link LogoutSuccessEventPublishingLogoutHandler}.
 *
 * @author Kazuki Shimizu
 */
public class LogoutSuccessEventPublishingLogoutHandlerTests {

	private LogoutSuccessEventPublishingLogoutHandler handler;

	private AnnotationConfigApplicationContext context;
	private MockHttpServletRequest request;
	private MockHttpServletResponse response;

	@Before
	public void setUp() {
		this.handler = new LogoutSuccessEventPublishingLogoutHandler();
		this.context = new AnnotationConfigApplicationContext(LocalContext.class);
		handler.setApplicationEventPublisher(context);

		this.request = new MockHttpServletRequest();
		this.response = new MockHttpServletResponse();
	}

	@After
	public void tearDown() {
		context.close();
	}

	@Test
	public void logout() {
		Authentication authentication = new TestingAuthenticationToken("test", "password");

		handler.logout(request, response, authentication);

		EventHandler eventHandler = context.getBean(EventHandler.class);
		assertThat(eventHandler.event.getAuthentication()).isSameAs(authentication);
	}

	@Test
	public void authenticationIsNull() {
		Authentication authentication = null;

		handler.logout(request, response, authentication);

		EventHandler eventHandler = context.getBean(EventHandler.class);
		assertThat(eventHandler.called).isFalse();
	}

	@Test
	public void applicationEventPublisherIsNull() {
		Authentication authentication = new TestingAuthenticationToken("test", "password");
		handler.setApplicationEventPublisher(null);

		handler.logout(request, response, authentication);

		EventHandler eventHandler = context.getBean(EventHandler.class);
		assertThat(eventHandler.called).isFalse();
	}

	@Configuration
	static class LocalContext {
		@Bean
		EventHandler eventHandler() {
			return new EventHandler();
		}
	}

	private static class EventHandler {
		boolean called;
		LogoutSuccessEvent event;

		@EventListener
		public void on(LogoutSuccessEvent event) {
			called = true;
			this.event = event;
		}
	}

}
