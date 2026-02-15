/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.access.expression;

import org.jspecify.annotations.Nullable;

import org.springframework.security.access.expression.AbstractSecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.access.expression.SecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.authorization.AuthorizationManagerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;

/**
 * @author Luke Taylor
 * @author Eddú Meléndez
 * @author Steve Riesenberg
 * @since 3.0
 */
public class DefaultWebSecurityExpressionHandler extends AbstractSecurityExpressionHandler<FilterInvocation>
		implements SecurityExpressionHandler<FilterInvocation> {

	private static final String DEFAULT_ROLE_PREFIX = "ROLE_";

	private String defaultRolePrefix = DEFAULT_ROLE_PREFIX;

	@Override
	@SuppressWarnings("deprecation")
	protected SecurityExpressionOperations createSecurityExpressionRoot(@Nullable Authentication authentication,
			FilterInvocation fi) {
		FilterInvocationExpressionRoot root = new FilterInvocationExpressionRoot(() -> authentication, fi);
		root.setAuthorizationManagerFactory(getAuthorizationManagerFactory());
		root.setPermissionEvaluator(getPermissionEvaluator());
		if (!DEFAULT_ROLE_PREFIX.equals(this.defaultRolePrefix)) {
			// Ensure SecurityExpressionRoot can strip the custom role prefix
			root.setDefaultRolePrefix(this.defaultRolePrefix);
		}
		return root;
	}

	/**
	 * Sets the {@link AuthenticationTrustResolver} to be used. The default is
	 * {@link AuthenticationTrustResolverImpl}.
	 * @param trustResolver the {@link AuthenticationTrustResolver} to use. Cannot be
	 * null.
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0")
	public void setTrustResolver(AuthenticationTrustResolver trustResolver) {
		getDefaultAuthorizationManagerFactory().setTrustResolver(trustResolver);
	}

	/**
	 * <p>
	 * Sets the default prefix to be added to
	 * {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasAnyRole(String...)}
	 * or
	 * {@link org.springframework.security.access.expression.SecurityExpressionRoot#hasRole(String)}.
	 * For example, if hasRole("ADMIN") or hasRole("ROLE_ADMIN") is passed in, then the
	 * role ROLE_ADMIN will be used when the defaultRolePrefix is "ROLE_" (default).
	 * </p>
	 *
	 * <p>
	 * If null or empty, then no default role prefix is used.
	 * </p>
	 * @param defaultRolePrefix the default prefix to add to roles. Default "ROLE_".
	 * @deprecated Use
	 * {@link #setAuthorizationManagerFactory(AuthorizationManagerFactory)} instead
	 */
	@Deprecated(since = "7.0")
	public void setDefaultRolePrefix(@Nullable String defaultRolePrefix) {
		if (defaultRolePrefix == null) {
			defaultRolePrefix = "";
		}
		getDefaultAuthorizationManagerFactory().setRolePrefix(defaultRolePrefix);
		this.defaultRolePrefix = defaultRolePrefix;
	}

}
