/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.ui.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;

import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContext;
import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;


/**
 * Declared in web.xml as <br><pre>&lt;listener&gt;
 * &lt;listener-class&gt;org.acegisecurity.ui.session.HttpSessionEventPublisher&lt;/listener-class&gt;&lt;/listener&gt;
 * </pre>Publishes <code>HttpSessionApplicationEvent</code>s to the Spring Root WebApplicationContext. Maps
 * javax.servlet.http.HttpSessionListener.sessionCreated() to {@link HttpSessionCreatedEvent}. Maps
 * javax.servlet.http.HttpSessionListener.sessionDestroyed() to {@link HttpSessionDestroyedEvent}.
 *
 * @author Ray Krueger
 */
public class HttpSessionEventPublisher implements HttpSessionListener, ServletContextListener {
    //~ Static fields/initializers =====================================================================================

    private static final Log log = LogFactory.getLog(HttpSessionEventPublisher.class);

    //~ Instance fields ================================================================================================

    private ApplicationContext appContext;
    private ServletContext servletContext = null;

    //~ Methods ========================================================================================================

    /**
     * Not implemented
     *
     * @param event
     */
    public void contextDestroyed(ServletContextEvent event) {}

    /**
     * Handled internally by a call to {@link WebApplicationContextUtils#getWebApplicationContext(javax.servlet.ServletContext)}.
     *
     * @param event the ServletContextEvent passed in by the container, event.getServletContext() will be used to get
     *        the WebApplicationContext
     */
    public void contextInitialized(ServletContextEvent event) {
        if (log.isDebugEnabled()) {
            log.debug("Received ServletContextEvent: " + event);
        }

        appContext = WebApplicationContextUtils.getWebApplicationContext(event.getServletContext());

        if (appContext == null) {
            log.warn("Web application context is null. Will delay initialization until it's first used.");
            servletContext = event.getServletContext();
        }
    }

    ApplicationContext getContext() {
        if (appContext == null) {
            appContext = WebApplicationContextUtils.getRequiredWebApplicationContext(servletContext);
        }

        return appContext;
    }

    /**
     * Handles the HttpSessionEvent by publishing a {@link HttpSessionCreatedEvent} to the application
     * appContext.
     *
     * @param event HttpSessionEvent passed in by the container
     */
    public void sessionCreated(HttpSessionEvent event) {
        HttpSessionCreatedEvent e = new HttpSessionCreatedEvent(event.getSession());

        if (log.isDebugEnabled()) {
            log.debug("Publishing event: " + e);
        }

        getContext().publishEvent(e);
    }

    /**
     * Handles the HttpSessionEvent by publishing a {@link HttpSessionDestroyedEvent} to the application
     * appContext.
     *
     * @param event The HttpSessionEvent pass in by the container
     */
    public void sessionDestroyed(HttpSessionEvent event) {
        HttpSessionDestroyedEvent e = new HttpSessionDestroyedEvent(event.getSession());

        if (log.isDebugEnabled()) {
            log.debug("Publishing event: " + e);
        }

        getContext().publishEvent(e);
    }
}
