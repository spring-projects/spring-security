/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web;

import org.springframework.security.web.access.WebInvocationPrivilegeEvaluator;

/**
 * Well-known keys which are used to store Spring Security information in request or
 * session scope.
 *
 * @author Luke Taylor
 * @author Rob Winch
 * @since 3.0.3
 */
public final class WebAttributes {

	/**
	 * Used to cache an {@code AccessDeniedException} in the request for rendering.
	 *
	 * @see org.springframework.security.web.access.AccessDeniedHandlerImpl
	 */
	public static final String ACCESS_DENIED_403 = "SPRING_SECURITY_403_EXCEPTION";

	/**
	 * Used to cache an authentication-failure exception in the session.
	 *
	 * @see org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler
	 */
	public static final String AUTHENTICATION_EXCEPTION = "SPRING_SECURITY_LAST_EXCEPTION";

	/**
	 * Set as a request attribute to override the default
	 * {@link WebInvocationPrivilegeEvaluator}
	 *
	 * @since 3.1.3
	 * @see WebInvocationPrivilegeEvaluator
	 */
	public static final String WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE = WebAttributes.class.getName()
			+ ".WEB_INVOCATION_PRIVILEGE_EVALUATOR_ATTRIBUTE";

}
