/* Copyright 2004, 2005 Acegi Technology Pty Limited
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

package net.sf.acegisecurity.ui.session;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.context.ApplicationContext;

import org.springframework.web.context.support.WebApplicationContextUtils;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;
import javax.servlet.http.HttpSessionEvent;
import javax.servlet.http.HttpSessionListener;


/**
 * Declared in web.xml as <br>
 * <code> &lt;listener&gt;<br>
 * &lt;listener-class&gt;net.sf.acegisecurity.ui.session.HttpSessionEventPublisher&lt;/listener-class&gt;<br>
 * &lt;/listener&gt;<br>
 * </code> Publishes <code>HttpSessionApplicationEvent</code>s to the Spring
 * Root WebApplicationContext. <br>
 * Maps javax.servlet.http.HttpSessionListener.sessionCreated() to {@link
 * HttpSessionCreatedEvent}. <br>
 * Maps javax.servlet.http.HttpSessionListener.sessionDestroyed() to {@link
 * HttpSessionDestroyedEvent}. <br>
 *
 * @author Ray Krueger
 */
public class HttpSessionEventPublisher implements HttpSessionListener,
    ServletContextListener {
    //~ Static fields/initializers =============================================

    private static final Log log = LogFactory.getLog(HttpSessionEventPublisher.class);

    //~ Instance fields ========================================================

    private ApplicationContext context;

    //~ Methods ================================================================

    /**
     * Not implemented
     *
     * @param event
     */
    public void contextDestroyed(ServletContextEvent event) {}

    /**
     * Handled internally by a call to {@link
     * org.springframework.web.context.support.WebApplicationContextUtils#getRequiredWebApplicationContext(javax.servlet.ServletContext)}
     *
     * @param event the ServletContextEvent passed in by the container,
     *        event.getServletContext() will be used to get the
     *        WebApplicationContext
     */
    public void contextInitialized(ServletContextEvent event) {
        setContext(WebApplicationContextUtils.getRequiredWebApplicationContext(
                event.getServletContext()));
    }

    /**
     * Handles the HttpSessionEvent by publishing a {@link
     * HttpSessionCreatedEvent} to the application context.
     *
     * @param event HttpSessionEvent passed in by the container
     */
    public void sessionCreated(HttpSessionEvent event) {
        HttpSessionCreatedEvent e = new HttpSessionCreatedEvent(event
                .getSession());

        log.debug("Publishing event: " + e);

        context.publishEvent(e);
    }

    /**
     * Handles the HttpSessionEvent by publishing a {@link
     * HttpSessionDestroyedEvent} to the application context.
     *
     * @param event The HttpSessionEvent pass in by the container
     */
    public void sessionDestroyed(HttpSessionEvent event) {
        HttpSessionDestroyedEvent e = new HttpSessionDestroyedEvent(event
                .getSession());

        log.debug("Publishing event: " + e);

        context.publishEvent(e);
    }

    /**
     * Package level method for testing and internal usage
     *
     * @param context The ApplicationContext this class will use to publish
     *        events
     */
    void setContext(ApplicationContext context) {
        this.context = context;
        log.debug("Using context: " + context);
    }
}
