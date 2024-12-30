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

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.HttpSessionEvent;
import jakarta.servlet.http.HttpSessionIdListener;
import jakarta.servlet.http.HttpSessionListener;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;
import org.springframework.context.ApplicationEvent;
import org.springframework.core.log.LogMessage;
import org.springframework.security.web.context.support.SecurityWebApplicationContextUtils;

/**
 * Declared in web.xml as
 *
 * <pre>
 * &lt;listener&gt;
 *     &lt;listener-class&gt;org.springframework.security.web.session.HttpSessionEventPublisher&lt;/listener-class&gt;
 * &lt;/listener&gt;
 * </pre>
 *
 * Publishes <code>HttpSessionApplicationEvent</code>s to the Spring Root
 * WebApplicationContext. Maps jakarta.servlet.http.HttpSessionListener.sessionCreated()
 * to {@link HttpSessionCreatedEvent}. Maps
 * jakarta.servlet.http.HttpSessionListener.sessionDestroyed() to
 * {@link HttpSessionDestroyedEvent}.
 *
 * @author Ray Krueger
 */
public class HttpSessionEventPublisher implements HttpSessionListener, HttpSessionIdListener {

	private static final String LOGGER_NAME = HttpSessionEventPublisher.class.getName();

	ApplicationContext getContext(ServletContext servletContext) {
		return SecurityWebApplicationContextUtils.findRequiredWebApplicationContext(servletContext);
	}

	/**
	 * Handles the HttpSessionEvent by publishing a {@link HttpSessionCreatedEvent} to the
	 * application appContext.
	 * @param event HttpSessionEvent passed in by the container
	 */
	@Override
	public void sessionCreated(HttpSessionEvent event) {
		extracted(event.getSession(), new HttpSessionCreatedEvent(event.getSession()));
	}

	/**
	 * Handles the HttpSessionEvent by publishing a {@link HttpSessionDestroyedEvent} to
	 * the application appContext.
	 * @param event The HttpSessionEvent pass in by the container
	 */
	@Override
	public void sessionDestroyed(HttpSessionEvent event) {
		extracted(event.getSession(), new HttpSessionDestroyedEvent(event.getSession()));
	}

	/**
	 * @inheritDoc
	 */
	@Override
	public void sessionIdChanged(HttpSessionEvent event, String oldSessionId) {
		extracted(event.getSession(), new HttpSessionIdChangedEvent(event.getSession(), oldSessionId));
	}

	private void extracted(HttpSession session, ApplicationEvent e) {
		Log log = LogFactory.getLog(LOGGER_NAME);
		log.debug(LogMessage.format("Publishing event: %s", e));
		getContext(session.getServletContext()).publishEvent(e);
	}

}
