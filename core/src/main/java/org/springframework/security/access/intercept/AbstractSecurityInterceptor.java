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

package org.springframework.security.access.intercept;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationEventPublisherAware;
import org.springframework.context.MessageSource;
import org.springframework.context.MessageSourceAware;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.event.AuthenticationCredentialsNotFoundEvent;
import org.springframework.security.access.event.AuthorizationFailureEvent;
import org.springframework.security.access.event.AuthorizedEvent;
import org.springframework.security.access.event.PublicInvocationEvent;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;

/**
 * Abstract class that implements security interception for secure objects.
 * <p>
 * The <code>AbstractSecurityInterceptor</code> will ensure the proper startup
 * configuration of the security interceptor. It will also implement the proper handling
 * of secure object invocations, namely:
 * <ol>
 * <li>Obtain the {@link Authentication} object from the
 * {@link SecurityContextHolder}.</li>
 * <li>Determine if the request relates to a secured or public invocation by looking up
 * the secure object request against the {@link SecurityMetadataSource}.</li>
 * <li>For an invocation that is secured (there is a list of <code>ConfigAttribute</code>s
 * for the secure object invocation):
 * <ol type="a">
 * <li>If either the
 * {@link org.springframework.security.core.Authentication#isAuthenticated()} returns
 * <code>false</code>, or the {@link #alwaysReauthenticate} is <code>true</code>,
 * authenticate the request against the configured {@link AuthenticationManager}. When
 * authenticated, replace the <code>Authentication</code> object on the
 * <code>SecurityContextHolder</code> with the returned value.</li>
 * <li>Authorize the request against the configured {@link AccessDecisionManager}.</li>
 * <li>Perform any run-as replacement via the configured {@link RunAsManager}.</li>
 * <li>Pass control back to the concrete subclass, which will actually proceed with
 * executing the object. A {@link InterceptorStatusToken} is returned so that after the
 * subclass has finished proceeding with execution of the object, its finally clause can
 * ensure the <code>AbstractSecurityInterceptor</code> is re-called and tidies up
 * correctly using {@link #finallyInvocation(InterceptorStatusToken)}.</li>
 * <li>The concrete subclass will re-call the <code>AbstractSecurityInterceptor</code> via
 * the {@link #afterInvocation(InterceptorStatusToken, Object)} method.</li>
 * <li>If the <code>RunAsManager</code> replaced the <code>Authentication</code> object,
 * return the <code>SecurityContextHolder</code> to the object that existed after the call
 * to <code>AuthenticationManager</code>.</li>
 * <li>If an <code>AfterInvocationManager</code> is defined, invoke the invocation manager
 * and allow it to replace the object due to be returned to the caller.</li>
 * </ol>
 * </li>
 * <li>For an invocation that is public (there are no <code>ConfigAttribute</code>s for
 * the secure object invocation):
 * <ol type="a">
 * <li>As described above, the concrete subclass will be returned an
 * <code>InterceptorStatusToken</code> which is subsequently re-presented to the
 * <code>AbstractSecurityInterceptor</code> after the secure object has been executed. The
 * <code>AbstractSecurityInterceptor</code> will take no further action when its
 * {@link #afterInvocation(InterceptorStatusToken, Object)} is called.</li>
 * </ol>
 * </li>
 * <li>Control again returns to the concrete subclass, along with the <code>Object</code>
 * that should be returned to the caller. The subclass will then return that result or
 * exception to the original caller.</li>
 * </ol>
 *
 * @author Ben Alex
 * @author Rob Winch
 */
public abstract class AbstractSecurityInterceptor
		implements InitializingBean, ApplicationEventPublisherAware, MessageSourceAware {

	protected final Log logger = LogFactory.getLog(getClass());

	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();

	private ApplicationEventPublisher eventPublisher;

	private AccessDecisionManager accessDecisionManager;

	private AfterInvocationManager afterInvocationManager;

	private AuthenticationManager authenticationManager = new NoOpAuthenticationManager();

	private RunAsManager runAsManager = new NullRunAsManager();

	private boolean alwaysReauthenticate = false;

	private boolean rejectPublicInvocations = false;

	private boolean validateConfigAttributes = true;

	private boolean publishAuthorizationSuccess = false;

	public void afterPropertiesSet() {
		Assert.notNull(getSecureObjectClass(), "Subclass must provide a non-null response to getSecureObjectClass()");
		Assert.notNull(this.messages, "A message source must be set");
		Assert.notNull(this.authenticationManager, "An AuthenticationManager is required");
		Assert.notNull(this.accessDecisionManager, "An AccessDecisionManager is required");
		Assert.notNull(this.runAsManager, "A RunAsManager is required");
		Assert.notNull(this.obtainSecurityMetadataSource(), "An SecurityMetadataSource is required");
		Assert.isTrue(this.obtainSecurityMetadataSource().supports(getSecureObjectClass()),
				() -> "SecurityMetadataSource does not support secure object class: " + getSecureObjectClass());
		Assert.isTrue(this.runAsManager.supports(getSecureObjectClass()),
				() -> "RunAsManager does not support secure object class: " + getSecureObjectClass());
		Assert.isTrue(this.accessDecisionManager.supports(getSecureObjectClass()),
				() -> "AccessDecisionManager does not support secure object class: " + getSecureObjectClass());

		if (this.afterInvocationManager != null) {
			Assert.isTrue(this.afterInvocationManager.supports(getSecureObjectClass()),
					() -> "AfterInvocationManager does not support secure object class: " + getSecureObjectClass());
		}

		if (this.validateConfigAttributes) {
			Collection<ConfigAttribute> attributeDefs = this.obtainSecurityMetadataSource().getAllConfigAttributes();

			if (attributeDefs == null) {
				logger.warn("Could not validate configuration attributes as the SecurityMetadataSource did not return "
						+ "any attributes from getAllConfigAttributes()");
				return;
			}

			Set<ConfigAttribute> unsupportedAttrs = new HashSet<>();

			for (ConfigAttribute attr : attributeDefs) {
				if (!this.runAsManager.supports(attr) && !this.accessDecisionManager.supports(attr)
						&& ((this.afterInvocationManager == null) || !this.afterInvocationManager.supports(attr))) {
					unsupportedAttrs.add(attr);
				}
			}

			if (unsupportedAttrs.size() != 0) {
				throw new IllegalArgumentException("Unsupported configuration attributes: " + unsupportedAttrs);
			}

			logger.debug("Validated configuration attributes");
		}
	}

	protected InterceptorStatusToken beforeInvocation(Object object) {
		Assert.notNull(object, "Object was null");
		final boolean debug = logger.isDebugEnabled();

		if (!getSecureObjectClass().isAssignableFrom(object.getClass())) {
			throw new IllegalArgumentException("Security invocation attempted for object " + object.getClass().getName()
					+ " but AbstractSecurityInterceptor only configured to support secure objects of type: "
					+ getSecureObjectClass());
		}

		Collection<ConfigAttribute> attributes = this.obtainSecurityMetadataSource().getAttributes(object);

		if (attributes == null || attributes.isEmpty()) {
			if (rejectPublicInvocations) {
				throw new IllegalArgumentException("Secure object invocation " + object
						+ " was denied as public invocations are not allowed via this interceptor. "
						+ "This indicates a configuration error because the "
						+ "rejectPublicInvocations property is set to 'true'");
			}

			if (debug) {
				logger.debug("Public object - authentication not attempted");
			}

			publishEvent(new PublicInvocationEvent(object));

			return null; // no further work post-invocation
		}

		if (debug) {
			logger.debug("Secure object: " + object + "; Attributes: " + attributes);
		}

		if (SecurityContextHolder.getContext().getAuthentication() == null) {
			credentialsNotFound(messages.getMessage("AbstractSecurityInterceptor.authenticationNotFound",
					"An Authentication object was not found in the SecurityContext"), object, attributes);
		}

		Authentication authenticated = authenticateIfRequired();

		// Attempt authorization
		try {
			this.accessDecisionManager.decide(authenticated, object, attributes);
		}
		catch (AccessDeniedException accessDeniedException) {
			publishEvent(new AuthorizationFailureEvent(object, attributes, authenticated, accessDeniedException));

			throw accessDeniedException;
		}

		if (debug) {
			logger.debug("Authorization successful");
		}

		if (publishAuthorizationSuccess) {
			publishEvent(new AuthorizedEvent(object, attributes, authenticated));
		}

		// Attempt to run as a different user
		Authentication runAs = this.runAsManager.buildRunAs(authenticated, object, attributes);

		if (runAs == null) {
			if (debug) {
				logger.debug("RunAsManager did not change Authentication object");
			}

			// no further work post-invocation
			return new InterceptorStatusToken(SecurityContextHolder.getContext(), false, attributes, object);
		}
		else {
			if (debug) {
				logger.debug("Switching to RunAs Authentication: " + runAs);
			}

			SecurityContext origCtx = SecurityContextHolder.getContext();
			SecurityContextHolder.setContext(SecurityContextHolder.createEmptyContext());
			SecurityContextHolder.getContext().setAuthentication(runAs);

			// need to revert to token.Authenticated post-invocation
			return new InterceptorStatusToken(origCtx, true, attributes, object);
		}
	}

	/**
	 * Cleans up the work of the <tt>AbstractSecurityInterceptor</tt> after the secure
	 * object invocation has been completed. This method should be invoked after the
	 * secure object invocation and before afterInvocation regardless of the secure object
	 * invocation returning successfully (i.e. it should be done in a finally block).
	 * @param token as returned by the {@link #beforeInvocation(Object)} method
	 */
	protected void finallyInvocation(InterceptorStatusToken token) {
		if (token != null && token.isContextHolderRefreshRequired()) {
			if (logger.isDebugEnabled()) {
				logger.debug("Reverting to original Authentication: " + token.getSecurityContext().getAuthentication());
			}

			SecurityContextHolder.setContext(token.getSecurityContext());
		}
	}

	/**
	 * Completes the work of the <tt>AbstractSecurityInterceptor</tt> after the secure
	 * object invocation has been completed.
	 * @param token as returned by the {@link #beforeInvocation(Object)} method
	 * @param returnedObject any object returned from the secure object invocation (may be
	 * <tt>null</tt>)
	 * @return the object the secure object invocation should ultimately return to its
	 * caller (may be <tt>null</tt>)
	 */
	protected Object afterInvocation(InterceptorStatusToken token, Object returnedObject) {
		if (token == null) {
			// public object
			return returnedObject;
		}

		finallyInvocation(token); // continue to clean in this method for passivity

		if (afterInvocationManager != null) {
			// Attempt after invocation handling
			try {
				returnedObject = afterInvocationManager.decide(token.getSecurityContext().getAuthentication(),
						token.getSecureObject(), token.getAttributes(), returnedObject);
			}
			catch (AccessDeniedException accessDeniedException) {
				AuthorizationFailureEvent event = new AuthorizationFailureEvent(token.getSecureObject(),
						token.getAttributes(), token.getSecurityContext().getAuthentication(), accessDeniedException);
				publishEvent(event);

				throw accessDeniedException;
			}
		}

		return returnedObject;
	}

	/**
	 * Checks the current authentication token and passes it to the AuthenticationManager
	 * if {@link org.springframework.security.core.Authentication#isAuthenticated()}
	 * returns false or the property <tt>alwaysReauthenticate</tt> has been set to true.
	 * @return an authenticated <tt>Authentication</tt> object.
	 */
	private Authentication authenticateIfRequired() {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication.isAuthenticated() && !alwaysReauthenticate) {
			if (logger.isDebugEnabled()) {
				logger.debug("Previously Authenticated: " + authentication);
			}

			return authentication;
		}

		authentication = authenticationManager.authenticate(authentication);

		// We don't authenticated.setAuthentication(true), because each provider should do
		// that
		if (logger.isDebugEnabled()) {
			logger.debug("Successfully Authenticated: " + authentication);
		}

		SecurityContextHolder.getContext().setAuthentication(authentication);

		return authentication;
	}

	/**
	 * Helper method which generates an exception containing the passed reason, and
	 * publishes an event to the application context.
	 * <p>
	 * Always throws an exception.
	 * @param reason to be provided in the exception detail
	 * @param secureObject that was being called
	 * @param configAttribs that were defined for the secureObject
	 */
	private void credentialsNotFound(String reason, Object secureObject, Collection<ConfigAttribute> configAttribs) {
		AuthenticationCredentialsNotFoundException exception = new AuthenticationCredentialsNotFoundException(reason);

		AuthenticationCredentialsNotFoundEvent event = new AuthenticationCredentialsNotFoundEvent(secureObject,
				configAttribs, exception);
		publishEvent(event);

		throw exception;
	}

	public AccessDecisionManager getAccessDecisionManager() {
		return accessDecisionManager;
	}

	public AfterInvocationManager getAfterInvocationManager() {
		return afterInvocationManager;
	}

	public AuthenticationManager getAuthenticationManager() {
		return this.authenticationManager;
	}

	public RunAsManager getRunAsManager() {
		return runAsManager;
	}

	/**
	 * Indicates the type of secure objects the subclass will be presenting to the
	 * abstract parent for processing. This is used to ensure collaborators wired to the
	 * {@code AbstractSecurityInterceptor} all support the indicated secure object class.
	 * @return the type of secure object the subclass provides services for
	 */
	public abstract Class<?> getSecureObjectClass();

	public boolean isAlwaysReauthenticate() {
		return alwaysReauthenticate;
	}

	public boolean isRejectPublicInvocations() {
		return rejectPublicInvocations;
	}

	public boolean isValidateConfigAttributes() {
		return validateConfigAttributes;
	}

	public abstract SecurityMetadataSource obtainSecurityMetadataSource();

	public void setAccessDecisionManager(AccessDecisionManager accessDecisionManager) {
		this.accessDecisionManager = accessDecisionManager;
	}

	public void setAfterInvocationManager(AfterInvocationManager afterInvocationManager) {
		this.afterInvocationManager = afterInvocationManager;
	}

	/**
	 * Indicates whether the <code>AbstractSecurityInterceptor</code> should ignore the
	 * {@link Authentication#isAuthenticated()} property. Defaults to <code>false</code>,
	 * meaning by default the <code>Authentication.isAuthenticated()</code> property is
	 * trusted and re-authentication will not occur if the principal has already been
	 * authenticated.
	 * @param alwaysReauthenticate <code>true</code> to force
	 * <code>AbstractSecurityInterceptor</code> to disregard the value of
	 * <code>Authentication.isAuthenticated()</code> and always re-authenticate the
	 * request (defaults to <code>false</code>).
	 */
	public void setAlwaysReauthenticate(boolean alwaysReauthenticate) {
		this.alwaysReauthenticate = alwaysReauthenticate;
	}

	public void setApplicationEventPublisher(ApplicationEventPublisher applicationEventPublisher) {
		this.eventPublisher = applicationEventPublisher;
	}

	public void setAuthenticationManager(AuthenticationManager newManager) {
		this.authenticationManager = newManager;
	}

	public void setMessageSource(MessageSource messageSource) {
		this.messages = new MessageSourceAccessor(messageSource);
	}

	/**
	 * Only {@code AuthorizationFailureEvent} will be published. If you set this property
	 * to {@code true}, {@code AuthorizedEvent}s will also be published.
	 * @param publishAuthorizationSuccess default value is {@code false}
	 */
	public void setPublishAuthorizationSuccess(boolean publishAuthorizationSuccess) {
		this.publishAuthorizationSuccess = publishAuthorizationSuccess;
	}

	/**
	 * By rejecting public invocations (and setting this property to <tt>true</tt>),
	 * essentially you are ensuring that every secure object invocation advised by
	 * <code>AbstractSecurityInterceptor</code> has a configuration attribute defined.
	 * This is useful to ensure a "fail safe" mode where undeclared secure objects will be
	 * rejected and configuration omissions detected early. An
	 * <tt>IllegalArgumentException</tt> will be thrown by the
	 * <tt>AbstractSecurityInterceptor</tt> if you set this property to <tt>true</tt> and
	 * an attempt is made to invoke a secure object that has no configuration attributes.
	 * @param rejectPublicInvocations set to <code>true</code> to reject invocations of
	 * secure objects that have no configuration attributes (by default it is
	 * <code>false</code> which treats undeclared secure objects as "public" or
	 * unauthorized).
	 */
	public void setRejectPublicInvocations(boolean rejectPublicInvocations) {
		this.rejectPublicInvocations = rejectPublicInvocations;
	}

	public void setRunAsManager(RunAsManager runAsManager) {
		this.runAsManager = runAsManager;
	}

	public void setValidateConfigAttributes(boolean validateConfigAttributes) {
		this.validateConfigAttributes = validateConfigAttributes;
	}

	private void publishEvent(ApplicationEvent event) {
		if (this.eventPublisher != null) {
			this.eventPublisher.publishEvent(event);
		}
	}

	private static class NoOpAuthenticationManager implements AuthenticationManager {

		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			throw new AuthenticationServiceException("Cannot authenticate " + authentication);
		}

	}

}
