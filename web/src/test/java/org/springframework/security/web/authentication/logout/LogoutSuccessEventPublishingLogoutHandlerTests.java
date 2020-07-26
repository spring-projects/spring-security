/*
 * Copyright 2002-2019 the original author or authors.
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

import org.junit.Test;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.event.LogoutSuccessEvent;
import org.springframework.security.core.Authentication;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * @author Onur Kagan Ozcan
 */
public class LogoutSuccessEventPublishingLogoutHandlerTests {

	@Test
	public void shouldPublishEvent() {
		LogoutSuccessEventPublishingLogoutHandler handler = new LogoutSuccessEventPublishingLogoutHandler();
		LogoutAwareEventPublisher eventPublisher = new LogoutAwareEventPublisher();
		handler.setApplicationEventPublisher(eventPublisher);

		handler.logout(new MockHttpServletRequest(), new MockHttpServletResponse(), mock(Authentication.class));

		assertThat(eventPublisher.flag).isTrue();
	}

	@Test
	public void shouldNotPublishEventWhenAuthenticationIsNull() {
		LogoutSuccessEventPublishingLogoutHandler handler = new LogoutSuccessEventPublishingLogoutHandler();
		LogoutAwareEventPublisher eventPublisher = new LogoutAwareEventPublisher();
		handler.setApplicationEventPublisher(eventPublisher);

		handler.logout(new MockHttpServletRequest(), new MockHttpServletResponse(), null);

		assertThat(eventPublisher.flag).isFalse();
	}

	private static class LogoutAwareEventPublisher implements ApplicationEventPublisher {

		Boolean flag = false;

		@Override
		public void publishEvent(Object event) {
			if (LogoutSuccessEvent.class.isAssignableFrom(event.getClass())) {
				this.flag = true;
			}
		}

	}

}
