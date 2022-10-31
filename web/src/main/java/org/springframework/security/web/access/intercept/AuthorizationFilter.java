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

package org.springframework.security.web.access.intercept;

import java.io.IOException;
import java.util.function.Supplier;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.ApplicationEventPublisher;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationEventPublisher;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.event.AuthorizationDeniedEvent;
import org.springframework.security.authorization.event.AuthorizationGrantedEvent;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * An authorization filter that restricts access to the URL using
 * {@link AuthorizationManager}.
 *
 * @author Evgeniy Cheban
 * @since 5.5
 */
public class AuthorizationFilter extends GenericFilterBean {

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
			.getContextHolderStrategy();

	private final AuthorizationManager<HttpServletRequest> authorizationManager;

	private AuthorizationEventPublisher eventPublisher = AuthorizationFilter::noPublish;

	private boolean observeOncePerRequest = false;

	private boolean filterErrorDispatch = true;

	private boolean filterAsyncDispatch = true;

	/**
	 * Creates an instance.
	 * @param authorizationManager the {@link AuthorizationManager} to use
	 */
	public AuthorizationFilter(AuthorizationManager<HttpServletRequest> authorizationManager) {
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.authorizationManager = authorizationManager;
	}

	@Override
	public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain)
			throws ServletException, IOException {

		HttpServletRequest request = (HttpServletRequest) servletRequest;
		HttpServletResponse response = (HttpServletResponse) servletResponse;

		if (this.observeOncePerRequest && isApplied(request)) {
			chain.doFilter(request, response);
			return;
		}

		if (skipDispatch(request)) {
			chain.doFilter(request, response);
			return;
		}

		String alreadyFilteredAttributeName = getAlreadyFilteredAttributeName();
		request.setAttribute(alreadyFilteredAttributeName, Boolean.TRUE);
		try {
			AuthorizationDecision decision = this.authorizationManager.check(this::getAuthentication, request);
			this.eventPublisher.publishAuthorizationEvent(this::getAuthentication, request, decision);
			if (decision != null && !decision.isGranted()) {
				throw new AccessDeniedException("Access Denied");
			}
			chain.doFilter(request, response);
		}
		finally {
			request.removeAttribute(alreadyFilteredAttributeName);
		}
	}

	private boolean skipDispatch(HttpServletRequest request) {
		if (DispatcherType.ERROR.equals(request.getDispatcherType()) && !this.filterErrorDispatch) {
			return true;
		}
		if (DispatcherType.ASYNC.equals(request.getDispatcherType()) && !this.filterAsyncDispatch) {
			return true;
		}
		return false;
	}

	private boolean isApplied(HttpServletRequest request) {
		return request.getAttribute(getAlreadyFilteredAttributeName()) != null;
	}

	private String getAlreadyFilteredAttributeName() {
		String name = getFilterName();
		if (name == null) {
			name = getClass().getName();
		}
		return name + ".APPLIED";
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

	private Authentication getAuthentication() {
		Authentication authentication = this.securityContextHolderStrategy.getContext().getAuthentication();
		if (authentication == null) {
			throw new AuthenticationCredentialsNotFoundException(
					"An Authentication object was not found in the SecurityContext");
		}
		return authentication;
	}

	/**
	 * Use this {@link AuthorizationEventPublisher} to publish
	 * {@link AuthorizationDeniedEvent}s and {@link AuthorizationGrantedEvent}s.
	 * @param eventPublisher the {@link ApplicationEventPublisher} to use
	 * @since 5.7
	 */
	public void setAuthorizationEventPublisher(AuthorizationEventPublisher eventPublisher) {
		Assert.notNull(eventPublisher, "eventPublisher cannot be null");
		this.eventPublisher = eventPublisher;
	}

	/**
	 * Gets the {@link AuthorizationManager} used by this filter
	 * @return the {@link AuthorizationManager}
	 */
	public AuthorizationManager<HttpServletRequest> getAuthorizationManager() {
		return this.authorizationManager;
	}

	/**
	 * Sets whether to filter all dispatcher types.
	 * @param shouldFilterAllDispatcherTypes should filter all dispatcher types. Default
	 * is {@code true}
	 * @since 5.7
	 */
	public void setShouldFilterAllDispatcherTypes(boolean shouldFilterAllDispatcherTypes) {
		this.observeOncePerRequest = !shouldFilterAllDispatcherTypes;
		this.filterErrorDispatch = shouldFilterAllDispatcherTypes;
		this.filterAsyncDispatch = shouldFilterAllDispatcherTypes;
	}

	private static <T> void noPublish(Supplier<Authentication> authentication, T object,
			AuthorizationDecision decision) {

	}

	public boolean isObserveOncePerRequest() {
		return this.observeOncePerRequest;
	}

	/**
	 * Sets whether this filter apply only once per request. By default, this is
	 * <code>true</code>, meaning the filter will only execute once per request. Sometimes
	 * users may wish it to execute more than once per request, such as when JSP forwards
	 * are being used and filter security is desired on each included fragment of the HTTP
	 * request.
	 * @param observeOncePerRequest whether the filter should only be applied once per
	 * request
	 */
	public void setObserveOncePerRequest(boolean observeOncePerRequest) {
		this.observeOncePerRequest = observeOncePerRequest;
	}

	/**
	 * If set to true, the filter will be applied to error dispatcher. Defaults to false.
	 * @param filterErrorDispatch whether the filter should be applied to error dispatcher
	 */
	public void setFilterErrorDispatch(boolean filterErrorDispatch) {
		this.filterErrorDispatch = filterErrorDispatch;
	}

	/**
	 * If set to true, the filter will be applied to the async dispatcher. Defaults to
	 * false.
	 * @param filterAsyncDispatch whether the filter should be applied to async dispatch
	 */
	public void setFilterAsyncDispatch(boolean filterAsyncDispatch) {
		this.filterAsyncDispatch = filterAsyncDispatch;
	}

}
