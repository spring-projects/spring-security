/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.web.context;

import java.util.function.Supplier;

import jakarta.servlet.AsyncContext;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.annotation.AnnotationUtils;
import org.springframework.core.log.LogMessage;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.Transient;
import org.springframework.security.core.context.DeferredSecurityContext;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.util.WebUtils;

/**
 * A {@code SecurityContextRepository} implementation which stores the security context in
 * the {@code HttpSession} between requests.
 * <p>
 * The {@code HttpSession} will be queried to retrieve the {@code SecurityContext} in the
 * <tt>loadContext</tt> method (using the key {@link #SPRING_SECURITY_CONTEXT_KEY} by
 * default). If a valid {@code SecurityContext} cannot be obtained from the
 * {@code HttpSession} for whatever reason, a fresh {@code SecurityContext} will be
 * created by calling by {@link SecurityContextHolder#createEmptyContext()} and this
 * instance will be returned instead.
 * <p>
 * When <tt>saveContext</tt> is called, the context will be stored under the same key,
 * provided
 * <ol>
 * <li>The value has changed</li>
 * <li>The configured <tt>AuthenticationTrustResolver</tt> does not report that the
 * contents represent an anonymous user</li>
 * </ol>
 * <p>
 * With the standard configuration, no {@code HttpSession} will be created during
 * <tt>loadContext</tt> if one does not already exist. When <tt>saveContext</tt> is called
 * at the end of the web request, and no session exists, a new {@code HttpSession} will
 * <b>only</b> be created if the supplied {@code SecurityContext} is not equal to an empty
 * {@code SecurityContext} instance. This avoids needless <code>HttpSession</code>
 * creation, but automates the storage of changes made to the context during the request.
 * Note that if {@link SecurityContextPersistenceFilter} is configured to eagerly create
 * sessions, then the session-minimisation logic applied here will not make any
 * difference. If you are using eager session creation, then you should ensure that the
 * <tt>allowSessionCreation</tt> property of this class is set to <tt>true</tt> (the
 * default).
 * <p>
 * If for whatever reason no {@code HttpSession} should <b>ever</b> be created (for
 * example, if Basic authentication is being used or similar clients that will never
 * present the same {@code jsessionid}), then {@link #setAllowSessionCreation(boolean)
 * allowSessionCreation} should be set to <code>false</code>. Only do this if you really
 * need to conserve server memory and ensure all classes using the
 * {@code SecurityContextHolder} are designed to have no persistence of the
 * {@code SecurityContext} between web requests.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class HttpSessionSecurityContextRepository implements SecurityContextRepository {

	/**
	 * The default key under which the security context will be stored in the session.
	 */
	public static final String SPRING_SECURITY_CONTEXT_KEY = "SPRING_SECURITY_CONTEXT";

	protected final Log logger = LogFactory.getLog(this.getClass());

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	/**
	 * SecurityContext instance used to check for equality with default (unauthenticated)
	 * content
	 */
	private Object contextObject = this.securityContextHolderStrategy.createEmptyContext();

	private boolean allowSessionCreation = true;

	private boolean disableUrlRewriting = false;

	private String springSecurityContextKey = SPRING_SECURITY_CONTEXT_KEY;

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	/**
	 * Gets the security context for the current request (if available) and returns it.
	 * <p>
	 * If the session is null, the context object is null or the context object stored in
	 * the session is not an instance of {@code SecurityContext}, a new context object
	 * will be generated and returned.
	 * @deprecated please see {@link SecurityContextRepository#loadContext}
	 */
	@Deprecated
	@Override
	public SecurityContext loadContext(HttpRequestResponseHolder requestResponseHolder) {
		HttpServletRequest request = requestResponseHolder.getRequest();
		HttpServletResponse response = requestResponseHolder.getResponse();
		HttpSession httpSession = request.getSession(false);
		SecurityContext context = readSecurityContextFromSession(httpSession);
		if (context == null) {
			context = generateNewContext();
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Created %s", context));
			}
		}
		if (response != null) {
			SaveToSessionResponseWrapper wrappedResponse = new SaveToSessionResponseWrapper(response, request,
					httpSession != null, context);
			wrappedResponse.setSecurityContextHolderStrategy(this.securityContextHolderStrategy);
			requestResponseHolder.setResponse(wrappedResponse);
			requestResponseHolder.setRequest(new SaveToSessionRequestWrapper(request, wrappedResponse));
		}
		return context;
	}

	@Override
	public DeferredSecurityContext loadDeferredContext(HttpServletRequest request) {
		Supplier<SecurityContext> supplier = () -> readSecurityContextFromSession(request.getSession(false));
		return new SupplierDeferredSecurityContext(supplier, this.securityContextHolderStrategy);
	}

	@Override
	public void saveContext(SecurityContext context, HttpServletRequest request, HttpServletResponse response) {
		SaveContextOnUpdateOrErrorResponseWrapper responseWrapper = WebUtils.getNativeResponse(response,
				SaveContextOnUpdateOrErrorResponseWrapper.class);
		if (responseWrapper == null) {
			saveContextInHttpSession(context, request);
			return;
		}
		responseWrapper.saveContext(context);
	}

	private void saveContextInHttpSession(SecurityContext context, HttpServletRequest request) {
		if (isTransient(context) || isTransient(context.getAuthentication())) {
			return;
		}
		SecurityContext emptyContext = generateNewContext();
		if (emptyContext.equals(context)) {
			HttpSession session = request.getSession(false);
			removeContextFromSession(context, session);
		}
		else {
			boolean createSession = this.allowSessionCreation;
			HttpSession session = request.getSession(createSession);
			setContextInSession(context, session);
		}
	}

	private void setContextInSession(SecurityContext context, HttpSession session) {
		if (session != null) {
			session.setAttribute(this.springSecurityContextKey, context);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Stored %s to HttpSession [%s]", context, session));
			}
		}
	}

	private void removeContextFromSession(SecurityContext context, HttpSession session) {
		if (session != null) {
			session.removeAttribute(this.springSecurityContextKey);
			if (this.logger.isDebugEnabled()) {
				this.logger.debug(LogMessage.format("Removed %s from HttpSession [%s]", context, session));
			}
		}
	}

	@Override
	public boolean containsContext(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null) {
			return false;
		}
		return session.getAttribute(this.springSecurityContextKey) != null;
	}

	/**
	 * @param httpSession the session obtained from the request.
	 */
	private SecurityContext readSecurityContextFromSession(HttpSession httpSession) {
		if (httpSession == null) {
			this.logger.trace("No HttpSession currently exists");
			return null;
		}
		// Session exists, so try to obtain a context from it.
		Object contextFromSession = httpSession.getAttribute(this.springSecurityContextKey);
		if (contextFromSession == null) {
			if (this.logger.isTraceEnabled()) {
				this.logger.trace(LogMessage.format("Did not find SecurityContext in HttpSession %s "
						+ "using the SPRING_SECURITY_CONTEXT session attribute", httpSession.getId()));
			}
			return null;
		}

		// We now have the security context object from the session.
		if (!(contextFromSession instanceof SecurityContext)) {
			this.logger.warn(LogMessage.format(
					"%s did not contain a SecurityContext but contained: '%s'; are you improperly "
							+ "modifying the HttpSession directly (you should always use SecurityContextHolder) "
							+ "or using the HttpSession attribute reserved for this class?",
					this.springSecurityContextKey, contextFromSession));
			return null;
		}

		if (this.logger.isTraceEnabled()) {
			this.logger
				.trace(LogMessage.format("Retrieved %s from %s", contextFromSession, this.springSecurityContextKey));
		}
		else if (this.logger.isDebugEnabled()) {
			this.logger.debug(LogMessage.format("Retrieved %s", contextFromSession));
		}
		// Everything OK. The only non-null return from this method.
		return (SecurityContext) contextFromSession;
	}

	/**
	 * By default, calls {@link SecurityContextHolder#createEmptyContext()} to obtain a
	 * new context (there should be no context present in the holder when this method is
	 * called). Using this approach the context creation strategy is decided by the
	 * {@link SecurityContextHolderStrategy} in use. The default implementations will
	 * return a new <tt>SecurityContextImpl</tt>.
	 * @return a new SecurityContext instance. Never null.
	 */
	protected SecurityContext generateNewContext() {
		return this.securityContextHolderStrategy.createEmptyContext();
	}

	/**
	 * If set to true (the default), a session will be created (if required) to store the
	 * security context if it is determined that its contents are different from the
	 * default empty context value.
	 * <p>
	 * Note that setting this flag to false does not prevent this class from storing the
	 * security context. If your application (or another filter) creates a session, then
	 * the security context will still be stored for an authenticated user.
	 * @param allowSessionCreation
	 */
	public void setAllowSessionCreation(boolean allowSessionCreation) {
		this.allowSessionCreation = allowSessionCreation;
	}

	/**
	 * Allows the use of session identifiers in URLs to be disabled. Off by default.
	 * @param disableUrlRewriting set to <tt>true</tt> to disable URL encoding methods in
	 * the response wrapper and prevent the use of <tt>jsessionid</tt> parameters.
	 */
	public void setDisableUrlRewriting(boolean disableUrlRewriting) {
		this.disableUrlRewriting = disableUrlRewriting;
	}

	/**
	 * Allows the session attribute name to be customized for this repository instance.
	 * @param springSecurityContextKey the key under which the security context will be
	 * stored. Defaults to {@link #SPRING_SECURITY_CONTEXT_KEY}.
	 */
	public void setSpringSecurityContextKey(String springSecurityContextKey) {
		Assert.hasText(springSecurityContextKey, "springSecurityContextKey cannot be empty");
		this.springSecurityContextKey = springSecurityContextKey;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy strategy) {
		this.securityContextHolderStrategy = strategy;
		this.contextObject = this.securityContextHolderStrategy.createEmptyContext();
	}

	private boolean isTransient(Object object) {
		if (object == null) {
			return false;
		}
		return AnnotationUtils.getAnnotation(object.getClass(), Transient.class) != null;
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 * null.
	 */
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		Assert.notNull(trustResolver, "trustResolver cannot be null");
		this.trustResolver = trustResolver;
	}

	private static class SaveToSessionRequestWrapper extends HttpServletRequestWrapper {

		private final SaveContextOnUpdateOrErrorResponseWrapper response;

		SaveToSessionRequestWrapper(HttpServletRequest request, SaveContextOnUpdateOrErrorResponseWrapper response) {
			super(request);
			this.response = response;
		}

		@Override
		public AsyncContext startAsync() {
			this.response.disableSaveOnResponseCommitted();
			return super.startAsync();
		}

		@Override
		public AsyncContext startAsync(ServletRequest servletRequest, ServletResponse servletResponse)
				throws IllegalStateException {
			this.response.disableSaveOnResponseCommitted();
			return super.startAsync(servletRequest, servletResponse);
		}

	}

	/**
	 * Wrapper that is applied to every request/response to update the
	 * <code>HttpSession</code> with the <code>SecurityContext</code> when a
	 * <code>sendError()</code> or <code>sendRedirect</code> happens. See SEC-398.
	 * <p>
	 * Stores the necessary state from the start of the request in order to make a
	 * decision about whether the security context has changed before saving it.
	 */
	final class SaveToSessionResponseWrapper extends SaveContextOnUpdateOrErrorResponseWrapper {

		private final Log logger = HttpSessionSecurityContextRepository.this.logger;

		private final HttpServletRequest request;

		private final boolean httpSessionExistedAtStartOfRequest;

		private final SecurityContext contextBeforeExecution;

		private final Authentication authBeforeExecution;

		private boolean isSaveContextInvoked;

		/**
		 * Takes the parameters required to call <code>saveContext()</code> successfully
		 * in addition to the request and the response object we are wrapping.
		 * @param request the request object (used to obtain the session, if one exists).
		 * @param httpSessionExistedAtStartOfRequest indicates whether there was a session
		 * in place before the filter chain executed. If this is true, and the session is
		 * found to be null, this indicates that it was invalidated during the request and
		 * a new session will now be created.
		 * @param context the context before the filter chain executed. The context will
		 * only be stored if it or its contents changed during the request.
		 */
		SaveToSessionResponseWrapper(HttpServletResponse response, HttpServletRequest request,
				boolean httpSessionExistedAtStartOfRequest, SecurityContext context) {
			super(response, HttpSessionSecurityContextRepository.this.disableUrlRewriting);
			this.request = request;
			this.httpSessionExistedAtStartOfRequest = httpSessionExistedAtStartOfRequest;
			this.contextBeforeExecution = context;
			this.authBeforeExecution = context.getAuthentication();
		}

		/**
		 * Stores the supplied security context in the session (if available) and if it
		 * has changed since it was set at the start of the request. If the
		 * AuthenticationTrustResolver identifies the current user as anonymous, then the
		 * context will not be stored.
		 * @param context the context object obtained from the SecurityContextHolder after
		 * the request has been processed by the filter chain.
		 * SecurityContextHolder.getContext() cannot be used to obtain the context as it
		 * has already been cleared by the time this method is called.
		 *
		 */
		@Override
		protected void saveContext(SecurityContext context) {
			if (isTransient(context)) {
				return;
			}
			final Authentication authentication = context.getAuthentication();
			if (isTransient(authentication)) {
				return;
			}
			HttpSession httpSession = this.request.getSession(false);
			String springSecurityContextKey = HttpSessionSecurityContextRepository.this.springSecurityContextKey;
			// See SEC-776
			if (authentication == null
					|| HttpSessionSecurityContextRepository.this.trustResolver.isAnonymous(authentication)) {
				if (httpSession != null && this.authBeforeExecution != null) {
					// SEC-1587 A non-anonymous context may still be in the session
					// SEC-1735 remove if the contextBeforeExecution was not anonymous
					httpSession.removeAttribute(springSecurityContextKey);
					this.isSaveContextInvoked = true;
				}
				if (this.logger.isDebugEnabled()) {
					if (authentication == null) {
						this.logger.debug("Did not store empty SecurityContext");
					}
					else {
						this.logger.debug("Did not store anonymous SecurityContext");
					}
				}
				return;
			}
			httpSession = (httpSession != null) ? httpSession : createNewSessionIfAllowed(context);
			// If HttpSession exists, store current SecurityContext but only if it has
			// actually changed in this thread (see SEC-37, SEC-1307, SEC-1528)
			if (httpSession != null) {
				// We may have a new session, so check also whether the context attribute
				// is set SEC-1561
				if (contextChanged(context) || httpSession.getAttribute(springSecurityContextKey) == null) {
					HttpSessionSecurityContextRepository.this.saveContextInHttpSession(context, this.request);
					this.isSaveContextInvoked = true;
				}
			}
		}

		private boolean contextChanged(SecurityContext context) {
			return this.isSaveContextInvoked || context != this.contextBeforeExecution
					|| context.getAuthentication() != this.authBeforeExecution;
		}

		private HttpSession createNewSessionIfAllowed(SecurityContext context) {
			if (this.httpSessionExistedAtStartOfRequest) {
				this.logger.debug("HttpSession is now null, but was not null at start of request; "
						+ "session was invalidated, so do not create a new session");
				return null;
			}
			if (!HttpSessionSecurityContextRepository.this.allowSessionCreation) {
				this.logger.debug("The HttpSession is currently null, and the "
						+ HttpSessionSecurityContextRepository.class.getSimpleName()
						+ " is prohibited from creating an HttpSession "
						+ "(because the allowSessionCreation property is false) - SecurityContext thus not "
						+ "stored for next request");
				return null;
			}
			// Generate a HttpSession only if we need to
			if (HttpSessionSecurityContextRepository.this.contextObject.equals(context)) {
				this.logger.debug(LogMessage.format(
						"HttpSession is null, but SecurityContext has not changed from "
								+ "default empty context %s so not creating HttpSession or storing SecurityContext",
						context));
				return null;
			}
			try {
				HttpSession session = this.request.getSession(true);
				this.logger.debug("Created HttpSession as SecurityContext is non-default");
				return session;
			}
			catch (IllegalStateException ex) {
				// Response must already be committed, therefore can't create a new
				// session
				this.logger.warn("Failed to create a session, as response has been committed. "
						+ "Unable to store SecurityContext.");
			}
			return null;
		}

	}

}
