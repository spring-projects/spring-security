/*
 * Copyright 2002-2022 the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.util.OnCommittedResponseWrapper;
import org.springframework.util.Assert;

/**
 * Base class for response wrappers which encapsulate the logic for storing a security
 * context and which store the <code>SecurityContext</code> when a
 * <code>sendError()</code>, <code>sendRedirect</code>,
 * <code>getOutputStream().close()</code>, <code>getOutputStream().flush()</code>,
 * <code>getWriter().close()</code>, or <code>getWriter().flush()</code> happens on the
 * same thread that this {@link SaveContextOnUpdateOrErrorResponseWrapper} was created.
 * See issue SEC-398 and SEC-2005.
 * <p>
 * Sub-classes should implement the {@link #saveContext(SecurityContext context)} method.
 * <p>
 * Support is also provided for disabling URL rewriting
 *
 * @author Luke Taylor
 * @author Marten Algesten
 * @author Rob Winch
 * @since 3.0
 * @deprecated Use
 * {@link SecurityContextRepository#loadDeferredContext(HttpServletRequest)} instead.
 */
@Deprecated
public abstract class SaveContextOnUpdateOrErrorResponseWrapper extends OnCommittedResponseWrapper {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private boolean contextSaved = false;

	// See SEC-1052
	private final boolean disableUrlRewriting;

	/**
	 * @param response the response to be wrapped
	 * @param disableUrlRewriting turns the URL encoding methods into null operations,
	 * preventing the use of URL rewriting to add the session identifier as a URL
	 * parameter.
	 */
	public SaveContextOnUpdateOrErrorResponseWrapper(HttpServletResponse response, boolean disableUrlRewriting) {
		super(response);
		this.disableUrlRewriting = disableUrlRewriting;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default action is to use
	 * the {@link SecurityContextHolderStrategy} stored in {@link SecurityContextHolder}.
	 *
	 * @since 5.8
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	/**
	 * Invoke this method to disable automatic saving of the {@link SecurityContext} when
	 * the {@link HttpServletResponse} is committed. This can be useful in the event that
	 * Async Web Requests are made which may no longer contain the {@link SecurityContext}
	 * on it.
	 */
	public void disableSaveOnResponseCommitted() {
		disableOnResponseCommitted();
	}

	/**
	 * Implements the logic for storing the security context.
	 * @param context the <tt>SecurityContext</tt> instance to store
	 */
	protected abstract void saveContext(SecurityContext context);

	/**
	 * Calls <code>saveContext()</code> with the current contents of the
	 * <tt>SecurityContextHolder</tt> as long as {@link #disableSaveOnResponseCommitted()
	 * ()} was not invoked.
	 */
	@Override
	protected void onResponseCommitted() {
		saveContext(this.securityContextHolderStrategy.getContext());
		this.contextSaved = true;
	}

	@Override
	public final String encodeRedirectURL(String url) {
		if (this.disableUrlRewriting) {
			return url;
		}
		return super.encodeRedirectURL(url);
	}

	@Override
	public final String encodeURL(String url) {
		if (this.disableUrlRewriting) {
			return url;
		}
		return super.encodeURL(url);
	}

	/**
	 * Tells if the response wrapper has called <code>saveContext()</code> because of this
	 * wrapper.
	 */
	public final boolean isContextSaved() {
		return this.contextSaved;
	}

}
