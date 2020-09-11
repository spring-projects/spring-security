/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.web.session;

import javax.servlet.http.HttpSessionEvent;

import org.junit.Test;

import org.springframework.mock.web.MockHttpSession;
import org.springframework.mock.web.MockServletContext;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.StaticWebApplicationContext;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalStateException;

/**
 * The HttpSessionEventPublisher tests
 *
 * @author Ray Krueger
 */
public class HttpSessionEventPublisherTests {

	/**
	 * It's not that complicated so we'll just run it straight through here.
	 */
	@Test
	public void publishedEventIsReceivedbyListener() {
		HttpSessionEventPublisher publisher = new HttpSessionEventPublisher();
		StaticWebApplicationContext context = new StaticWebApplicationContext();
		MockServletContext servletContext = new MockServletContext();
		servletContext.setAttribute(WebApplicationContext.ROOT_WEB_APPLICATION_CONTEXT_ATTRIBUTE, context);
		context.setServletContext(servletContext);
		context.registerSingleton("listener", MockApplicationListener.class, null);
		context.refresh();
		MockHttpSession session = new MockHttpSession(servletContext);
		MockApplicationListener listener = (MockApplicationListener) context.getBean("listener");
		HttpSessionEvent event = new HttpSessionEvent(session);
		publisher.sessionCreated(event);
		assertThat(listener.getCreatedEvent()).isNotNull();
		assertThat(listener.getDestroyedEvent()).isNull();
		assertThat(listener.getCreatedEvent().getSession()).isEqualTo(session);
		listener.setCreatedEvent(null);
		listener.setDestroyedEvent(null);
		publisher.sessionDestroyed(event);
		assertThat(listener.getDestroyedEvent()).isNotNull();
		assertThat(listener.getCreatedEvent()).isNull();
		assertThat(listener.getDestroyedEvent().getSession()).isEqualTo(session);
		publisher.sessionIdChanged(event, "oldSessionId");
		assertThat(listener.getSessionIdChangedEvent()).isNotNull();
		assertThat(listener.getSessionIdChangedEvent().getOldSessionId()).isEqualTo("oldSessionId");
		listener.setSessionIdChangedEvent(null);
	}

	@Test
	public void publishedEventIsReceivedbyListenerChildContext() {
		HttpSessionEventPublisher publisher = new HttpSessionEventPublisher();
		StaticWebApplicationContext context = new StaticWebApplicationContext();
		MockServletContext servletContext = new MockServletContext();
		servletContext.setAttribute("org.springframework.web.servlet.FrameworkServlet.CONTEXT.dispatcher", context);
		context.setServletContext(servletContext);
		context.registerSingleton("listener", MockApplicationListener.class, null);
		context.refresh();
		MockHttpSession session = new MockHttpSession(servletContext);
		MockApplicationListener listener = (MockApplicationListener) context.getBean("listener");
		HttpSessionEvent event = new HttpSessionEvent(session);
		publisher.sessionCreated(event);
		assertThat(listener.getCreatedEvent()).isNotNull();
		assertThat(listener.getDestroyedEvent()).isNull();
		assertThat(listener.getCreatedEvent().getSession()).isEqualTo(session);
		listener.setCreatedEvent(null);
		listener.setDestroyedEvent(null);
		publisher.sessionDestroyed(event);
		assertThat(listener.getDestroyedEvent()).isNotNull();
		assertThat(listener.getCreatedEvent()).isNull();
		assertThat(listener.getDestroyedEvent().getSession()).isEqualTo(session);
		publisher.sessionIdChanged(event, "oldSessionId");
		assertThat(listener.getSessionIdChangedEvent()).isNotNull();
		assertThat(listener.getSessionIdChangedEvent().getOldSessionId()).isEqualTo("oldSessionId");
		listener.setSessionIdChangedEvent(null);
	}

	// SEC-2599
	@Test
	public void sessionCreatedNullApplicationContext() {
		HttpSessionEventPublisher publisher = new HttpSessionEventPublisher();
		MockServletContext servletContext = new MockServletContext();
		MockHttpSession session = new MockHttpSession(servletContext);
		HttpSessionEvent event = new HttpSessionEvent(session);
		assertThatIllegalStateException().isThrownBy(() -> publisher.sessionCreated(event));
	}

	@Test // SEC-2599
	public void sessionDestroyedNullApplicationContext() {
		HttpSessionEventPublisher publisher = new HttpSessionEventPublisher();
		MockServletContext servletContext = new MockServletContext();
		MockHttpSession session = new MockHttpSession(servletContext);
		HttpSessionEvent event = new HttpSessionEvent(session);
		assertThatIllegalStateException().isThrownBy(() -> publisher.sessionDestroyed(event));
	}

	@Test
	public void sessionIdChangeNullApplicationContext() {
		HttpSessionEventPublisher publisher = new HttpSessionEventPublisher();
		MockServletContext servletContext = new MockServletContext();
		MockHttpSession session = new MockHttpSession(servletContext);
		HttpSessionEvent event = new HttpSessionEvent(session);
		assertThatIllegalStateException().isThrownBy(() -> publisher.sessionIdChanged(event, "oldSessionId"));
	}

}
