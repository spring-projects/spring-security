/*
 * Copyright 2005-2007 the original author or authors.
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

package org.springframework.security.context;

import java.lang.reflect.Method;

import javax.portlet.ActionRequest;
import javax.portlet.ActionResponse;
import javax.portlet.PortletException;
import javax.portlet.PortletRequest;
import javax.portlet.PortletResponse;
import javax.portlet.PortletSession;
import javax.portlet.RenderRequest;
import javax.portlet.RenderResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.springframework.util.ReflectionUtils;
import org.springframework.web.portlet.HandlerInterceptor;
import org.springframework.web.portlet.ModelAndView;

/**
 * <p>This interceptor populates the {@link SecurityContextHolder} with information obtained from the
 * <code>PortletSession</code>.  It is applied to both <code>ActionRequest</code>s and
 * <code>RenderRequest</code>s</p>
 *
 * <p>The <code>PortletSession</code> will be queried to retrieve the <code>SecurityContext</code> that should
 * be stored against the <code>SecurityContextHolder</code> for the duration of the portlet request. At the
 * end of the request, any updates made to the <code>SecurityContextHolder</code> will be persisted back to the
 * <code>PortletSession</code> by this interceptor.</p>
 *
 * <p> If a valid <code>SecurityContext</code> cannot be obtained from the <code>PortletSession</code> for
 * whatever reason, a fresh <code>SecurityContext</code> will be created and used instead. The created object
 * will be of the instance defined by the {@link #setContext(Class)} method (which defaults to
 * {@link org.springframework.security.context.SecurityContextImpl}. </p>
 *
 * <p>A <code>PortletSession</code> may be created by this interceptor if one does not already exist.  If at the
 * end of the portlet request the <code>PortletSession</code> does not exist, one will <b>only</b> be created if
 * the current contents of the <code>SecurityContextHolder</code> are not the {@link java.lang.Object#equals}
 * to a <code>new</code> instance of {@link #context}.  This avoids needless <code>PortletSession</code> creation,
 * and automates the storage of changes made to the <code>SecurityContextHolder</code>. There is one exception to
 * this rule, that is if the {@link #forceEagerSessionCreation} property is <code>true</code>, in which case
 * sessions will always be created irrespective of normal session-minimization logic (the default is
 * <code>false</code>, as this is resource intensive and not recommended).</p>
 *
 * <p>If for whatever reason no <code>PortletSession</code> should <b>ever</b> be created, the
 * {@link #allowSessionCreation} property should be set to <code>false</code>. Only do this if you really need
 * to conserve server memory and ensure all classes using the <code>SecurityContextHolder</code> are designed to
 * have no persistence of the <code>SecurityContext</code> between web requests. Please note that if
 * {@link #forceEagerSessionCreation} is <code>true</code>, the <code>allowSessionCreation</code> must also be
 * <code>true</code> (setting it to <code>false</code> will cause a startup-time error).</p>

 * <p>This interceptor <b>must</b> be executed <b>before</p> any authentication processing mechanisms. These
 * mechanisms (specifically {@link org.springframework.security.ui.portlet.PortletProcessingInterceptor}) expect the
 * <code>SecurityContextHolder</code> to contain a valid <code>SecurityContext</code> by the time they execute.</p>
 *
 * <p>An important nuance to this interceptor is that (by default) the <code>SecurityContext</code> is stored
 * into the <code>APPLICATION_SCOPE</code> of the <code>PortletSession</code>.  This doesn't just mean you will be
 * sharing it with all the other portlets in your webapp (which is generally a good idea).  It also means that (if
 * you have done all the other appropriate magic), you will share this <code>SecurityContext</code> with servlets in
 * your webapp.  This is very useful if you have servlets serving images or processing AJAX calls from your portlets
 * since they can now use the {@link HttpSessionContextIntegrationFilter} to access the same <code>SecurityContext<code>
 * object from the session.  This allows these calls to be secured as well as the portlet calls.</p>
 *
 * Much of the logic of this interceptor comes from the {@link HttpSessionContextIntegrationFilter} class which
 * fills the same purpose on the servlet side.  Ben Alex and Patrick Burlson are listed as authors here because they
 * are the authors of that class and there are blocks of code that essentially identical between the two. (Making this
 * a good candidate for refactoring someday.)
 *
 * <p>Unlike <code>HttpSessionContextIntegrationFilter</code>, this interceptor does not check to see if it is
 * getting applied multiple times.  This shouldn't be a problem since the application of interceptors is under the
 * control of the Spring Portlet MVC framework and tends to be more explicit and more predictable than the application
 * of filters.  However, you should still be careful to only apply this inteceptor to your request once.</p>
 *
 * @author John A. Lewis
 * @author Ben Alex
 * @author Patrick Burleson
 * @since 2.0
 * @version $Id$
 */
public class PortletSessionContextIntegrationInterceptor
		implements InitializingBean, HandlerInterceptor {

	//~ Static fields/initializers =====================================================================================

	protected static final Log logger = LogFactory.getLog(PortletSessionContextIntegrationInterceptor.class);

	public static final String SPRING_SECURITY_CONTEXT_KEY = HttpSessionContextIntegrationFilter.SPRING_SECURITY_CONTEXT_KEY;

	private static final String SESSION_EXISTED = PortletSessionContextIntegrationInterceptor.class.getName() + ".SESSION_EXISTED";
	private static final String CONTEXT_HASHCODE = PortletSessionContextIntegrationInterceptor.class.getName() + ".CONTEXT_HASHCODE";

	//~ Instance fields ================================================================================================

	private Class context = SecurityContextImpl.class;

	private Object contextObject;

	/**
	 * Indicates if this interceptor can create a <code>PortletSession</code> if
	 * needed (sessions are always created sparingly, but setting this value to
	 * <code>false</code> will prohibit sessions from ever being created).
	 * Defaults to <code>true</code>. Do not set to <code>false</code> if
	 * you are have set {@link #forceEagerSessionCreation} to <code>true</code>,
	 * as the properties would be in conflict.
	 */
	private boolean allowSessionCreation = true;

	/**
	 * Indicates if this interceptor is required to create a <code>PortletSession</code>
	 * for every request before proceeding through the request process, even if the
	 * <code>PortletSession</code> would not ordinarily have been created. By
	 * default this is <code>false</code>, which is entirely appropriate for
	 * most circumstances as you do not want a <code>PortletSession</code>
	 * created unless the interceptor actually needs one. It is envisaged the main
	 * situation in which this property would be set to <code>true</code> is
	 * if using other interceptors that depend on a <code>PortletSession</code>
	 * already existing. This is only required in specialized cases, so leave it set to
	 * <code>false</code> unless you have an actual requirement and aware of the
	 * session creation overhead.
	 */
	private boolean forceEagerSessionCreation = false;

	/**
	 * Indicates whether the <code>SecurityContext</code> will be cloned from
	 * the <code>PortletSession</code>. The default is to simply reference
	 * (the default is <code>false</code>). The default may cause issues if
	 * concurrent threads need to have a different security identity from other
	 * threads being concurrently processed that share the same
	 * <code>PortletSession</code>. In most normal environments this does not
	 * represent an issue, as changes to the security identity in one thread is
	 * allowed to affect the security identity in other threads associated with
	 * the same <code>PortletSession</code>. For unusual cases where this is not
	 * permitted, change this value to <code>true</code> and ensure the
	 * {@link #context} is set to a <code>SecurityContext</code> that
	 * implements {@link Cloneable} and overrides the <code>clone()</code>
	 * method.
	 */
	private boolean cloneFromPortletSession = false;

	/**
	 * Indicates wether the <code>APPLICATION_SCOPE</code> mode of the
	 * <code>PortletSession</code> should be used for storing the
	 * <code>SecurityContext</code>.  The default is </code>true</code>.
	 * This allows it to be shared between the portlets in the webapp and
	 * potentially with servlets in the webapp as well. If this is set to
	 * <code>false</code>, then the <code>PORTLET_SCOPE</code> will be used
	 * instead.
	 */
	private boolean useApplicationScopePortletSession = true;


	//~ Constructors ===================================================================================================

	public PortletSessionContextIntegrationInterceptor() throws PortletException {
		this.contextObject = generateNewContext();
	}

	//~ Methods ========================================================================================================

	public void afterPropertiesSet() throws Exception {

		// check that the value of context is legal
		if ((this.context == null) || (!SecurityContext.class.isAssignableFrom(this.context))) {
			throw new IllegalArgumentException("context must be defined and implement SecurityContext "
					+ "(typically use org.springframework.security.context.SecurityContextImpl; existing class is "
					+ this.context + ")");
		}

		// check that session creation options make sense
		if ((forceEagerSessionCreation == true) && (allowSessionCreation == false)) {
			throw new IllegalArgumentException(
					"If using forceEagerSessionCreation, you must set allowSessionCreation to also be true");
		}
	}

	public boolean preHandleAction(ActionRequest request, ActionResponse response,
			Object handler) throws Exception {
		// call to common preHandle method
		return preHandle(request, response, handler);
	}

	public boolean preHandleRender(RenderRequest request, RenderResponse response,
			Object handler) throws Exception {
		// call to common preHandle method
		return preHandle(request, response, handler);
	}

	public void postHandleRender(RenderRequest request, RenderResponse response,
			Object handler, ModelAndView modelAndView) throws Exception {
		// no-op
	}

	public void afterActionCompletion(ActionRequest request, ActionResponse response,
			Object handler, Exception ex) throws Exception {
		// call to common afterCompletion method
		afterCompletion(request, response, handler, ex);
	}

	public void afterRenderCompletion(RenderRequest request, RenderResponse response,
			Object handler, Exception ex) throws Exception {
		// call to common afterCompletion method
		afterCompletion(request, response, handler, ex);
	}


	private boolean preHandle(PortletRequest request, PortletResponse response,
			Object handler) throws Exception {

		PortletSession portletSession = null;
		boolean portletSessionExistedAtStartOfRequest = false;

		// see if the portlet session already exists (or should be eagerly created)
		try {
			portletSession = request.getPortletSession(forceEagerSessionCreation);
		} catch (IllegalStateException ignored) {}

		// if there is a session, then see if there is a context to bring in
		if (portletSession != null) {

			// remember that the session already existed
			portletSessionExistedAtStartOfRequest = true;

			// attempt to retrieve the context from the session
			Object contextFromSessionObject = portletSession.getAttribute(SPRING_SECURITY_CONTEXT_KEY, portletSessionScope());

			// if we got a context then place it into the holder
			if (contextFromSessionObject != null) {

				// if we are supposed to clone it, then do so
				if (cloneFromPortletSession) {
					Assert.isInstanceOf(Cloneable.class, contextFromSessionObject,
							"Context must implement Clonable and provide a Object.clone() method");
					try {
						Method m = contextFromSessionObject.getClass().getMethod("clone", new Class[] {});
						if (!m.isAccessible()) {
							m.setAccessible(true);
						}
						contextFromSessionObject = m.invoke(contextFromSessionObject, new Object[] {});
					}
					catch (Exception ex) {
						ReflectionUtils.handleReflectionException(ex);
					}
				}

				// if what we got is a valid context then place it into the holder, otherwise create a new one
				if (contextFromSessionObject instanceof SecurityContext) {
					if (logger.isDebugEnabled())
						logger.debug("Obtained from SPRING_SECURITY_CONTEXT a valid SecurityContext and "
								+ "set to SecurityContextHolder: '" + contextFromSessionObject + "'");
					SecurityContextHolder.setContext((SecurityContext) contextFromSessionObject);
				} else {
					if (logger.isWarnEnabled())
						logger.warn("SPRING_SECURITY_CONTEXT did not contain a SecurityContext but contained: '"
										+ contextFromSessionObject
										+ "'; are you improperly modifying the PortletSession directly "
										+ "(you should always use SecurityContextHolder) or using the PortletSession attribute "
										+ "reserved for this class? - new SecurityContext instance associated with "
										+ "SecurityContextHolder");
					SecurityContextHolder.setContext(generateNewContext());
				}

			} else {

				// there was no context in the session, so create a new context and put it in the holder
				if (logger.isDebugEnabled())
					logger.debug("PortletSession returned null object for SPRING_SECURITY_CONTEXT - new "
							+ "SecurityContext instance associated with SecurityContextHolder");
				SecurityContextHolder.setContext(generateNewContext());
			}

		} else {

			// there was no session, so create a new context and place it in the holder
			if (logger.isDebugEnabled())
				logger.debug("No PortletSession currently exists - new SecurityContext instance "
						+ "associated with SecurityContextHolder");
			SecurityContextHolder.setContext(generateNewContext());

		}

		// place attributes onto the request to remember if the session existed and the hashcode of the context
		request.setAttribute(SESSION_EXISTED, new Boolean(portletSessionExistedAtStartOfRequest));
		request.setAttribute(CONTEXT_HASHCODE, new Integer(SecurityContextHolder.getContext().hashCode()));

		return true;
	}

	private void afterCompletion(PortletRequest request, PortletResponse response,
			Object handler, Exception ex) throws Exception {

		PortletSession portletSession = null;

		// retrieve the attributes that remember if the session existed and the hashcode of the context
		boolean portletSessionExistedAtStartOfRequest = ((Boolean)request.getAttribute(SESSION_EXISTED)).booleanValue();
		int oldContextHashCode = ((Integer)request.getAttribute(CONTEXT_HASHCODE)).intValue();

		// try to retrieve an existing portlet session
		try {
			portletSession = request.getPortletSession(false);
		} catch (IllegalStateException ignored) {}

		// if there is now no session but there was one at the beginning then it must have been invalidated
		if ((portletSession == null) && portletSessionExistedAtStartOfRequest) {
			if (logger.isDebugEnabled())
				logger.debug("PortletSession is now null, but was not null at start of request; "
						+ "session was invalidated, so do not create a new session");
		}

		// create a new portlet session if we need to
		if ((portletSession == null) && !portletSessionExistedAtStartOfRequest) {

			// if we're not allowed to create a new session, then report that
			if (!allowSessionCreation) {
				if (logger.isDebugEnabled())
					logger.debug("The PortletSession is currently null, and the "
							+ "PortletSessionContextIntegrationInterceptor is prohibited from creating a PortletSession "
							+ "(because the allowSessionCreation property is false) - SecurityContext thus not "
							+ "stored for next request");
			}
			// if the context was changed during the request, then go ahead and create a session
			else if (!contextObject.equals(SecurityContextHolder.getContext())) {
				if (logger.isDebugEnabled())
					logger.debug("PortletSession being created as SecurityContextHolder contents are non-default");
				try {
					portletSession = request.getPortletSession(true);
				} catch (IllegalStateException ignored) {}
			}
			// if nothing in the context changed, then don't bother to create a session
			else {
				if (logger.isDebugEnabled())
					logger.debug("PortletSession is null, but SecurityContextHolder has not changed from default: ' "
							+ SecurityContextHolder.getContext()
							+ "'; not creating PortletSession or storing SecurityContextHolder contents");
			}
		}

		// if the session exists and the context has changes, then store the context back into the session
		if ((portletSession != null)
			&& (SecurityContextHolder.getContext().hashCode() != oldContextHashCode)) {
			portletSession.setAttribute(SPRING_SECURITY_CONTEXT_KEY,	SecurityContextHolder.getContext(), portletSessionScope());
			if (logger.isDebugEnabled())
				logger.debug("SecurityContext stored to PortletSession: '"
					+ SecurityContextHolder.getContext() + "'");
		}

		// remove the contents of the holder
		SecurityContextHolder.clearContext();
		if (logger.isDebugEnabled())
			logger.debug("SecurityContextHolder set to new context, as request processing completed");

	}


	/**
	 * Creates a new <code>SecurityContext</code> object.  The specific class is
	 * determined by the setting of the {@link #context} property.
	 * @return the new <code>SecurityContext</code>
	 * @throws PortletException if the creation throws an <code>InstantiationException</code> or
	 *     an <code>IllegalAccessException</code>, then this method will wrap them in a
	 *     <code>PortletException</code>
	 */
	public SecurityContext generateNewContext() throws PortletException {
		try {
			return (SecurityContext) this.context.newInstance();
		} catch (InstantiationException ie) {
			throw new PortletException(ie);
		} catch (IllegalAccessException iae) {
			throw new PortletException(iae);
		}
	}


	private int portletSessionScope() {
		// return the appropriate scope setting based on our property value
		return (this.useApplicationScopePortletSession ?
			PortletSession.APPLICATION_SCOPE :	PortletSession.PORTLET_SCOPE);
	}


	public Class getContext() {
		return context;
	}

	public void setContext(Class secureContext) {
		this.context = secureContext;
	}

	public boolean isAllowSessionCreation() {
		return allowSessionCreation;
	}

	public void setAllowSessionCreation(boolean allowSessionCreation) {
		this.allowSessionCreation = allowSessionCreation;
	}

	public boolean isForceEagerSessionCreation() {
		return forceEagerSessionCreation;
	}

	public void setForceEagerSessionCreation(boolean forceEagerSessionCreation) {
		this.forceEagerSessionCreation = forceEagerSessionCreation;
	}

	public boolean isCloneFromPortletSession() {
		return cloneFromPortletSession;
	}

	public void setCloneFromPortletSession(boolean cloneFromPortletSession) {
		this.cloneFromPortletSession = cloneFromPortletSession;
	}

	public boolean isUseApplicationScopePortletSession() {
		return useApplicationScopePortletSession;
	}

	public void setUseApplicationScopePortletSession(
			boolean useApplicationScopePortletSession) {
		this.useApplicationScopePortletSession = useApplicationScopePortletSession;
	}

}
