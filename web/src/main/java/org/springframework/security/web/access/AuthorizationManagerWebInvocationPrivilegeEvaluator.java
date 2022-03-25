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

package org.springframework.security.web.access;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;
import org.springframework.web.context.ServletContextAware;

/**
 * An implementation of {@link WebInvocationPrivilegeEvaluator} which delegates the checks
 * to an instance of {@link AuthorizationManager}
 *
 * @author Marcus Da Coregio
 * @since 5.5.5
 */
public final class AuthorizationManagerWebInvocationPrivilegeEvaluator
		implements WebInvocationPrivilegeEvaluator, ServletContextAware {

	private final AuthorizationManager<HttpServletRequest> authorizationManager;

	private ServletContext servletContext;

	public AuthorizationManagerWebInvocationPrivilegeEvaluator(
			AuthorizationManager<HttpServletRequest> authorizationManager) {
		Assert.notNull(authorizationManager, "authorizationManager cannot be null");
		this.authorizationManager = authorizationManager;
	}

	@Override
	public boolean isAllowed(String uri, Authentication authentication) {
		return isAllowed(null, uri, null, authentication);
	}

	@Override
	public boolean isAllowed(String contextPath, String uri, String method, Authentication authentication) {
		FilterInvocation filterInvocation = new FilterInvocation(contextPath, uri, method, this.servletContext);
		AuthorizationDecision decision = this.authorizationManager.check(() -> authentication,
				filterInvocation.getHttpRequest());
		return decision == null || decision.isGranted();
	}

	@Override
	public void setServletContext(ServletContext servletContext) {
		this.servletContext = servletContext;
	}

}
