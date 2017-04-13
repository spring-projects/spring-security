/*
 * Copyright 2017-2017 the original author or authors.
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
package org.springframework.security.abac;


import org.aopalliance.intercept.MethodInvocation;
import org.springframework.context.ApplicationContext;
import org.springframework.security.abac.model.PolicyChecker;
import org.springframework.security.abac.model.PolicyService;
import org.springframework.security.abac.service.json.JsonFilePolicyServiceImpl;
import org.springframework.security.access.expression.method.DefaultMethodSecurityExpressionHandler;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;

/**
 * Default implementation to be able to use spring-abac
 * Initialize it in your @Configuration
 *
 * @author Renato Soppelsa
 * @since 5.0.0
 */
public class AbacMethodSecurityExpressionHandler extends DefaultMethodSecurityExpressionHandler {

	private AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();
	private PolicyService policyService;

	/**
	 * Default AbacMethodSecurityExpressionHandler with JsonFilePolicyService (reading policies from default json file)
	 *
	 * @param applicationContext Spring application context
	 */
	public AbacMethodSecurityExpressionHandler(ApplicationContext applicationContext) {
		this(applicationContext, new JsonFilePolicyServiceImpl(null));
	}

	/**
	 * @param applicationContext Spring application context
	 * @param policyService      @JdbcpoliceServiceImpl or your own implementation of @PolicyService
	 */
	public AbacMethodSecurityExpressionHandler(ApplicationContext applicationContext, PolicyService policyService) {
		super();
		setApplicationContext(applicationContext);
		this.policyService = policyService;
	}

	@Override
	protected MethodSecurityExpressionOperations createSecurityExpressionRoot(
		Authentication authentication, MethodInvocation invocation) {
		PolicyChecker policyChecker = new DefaultPolicyCheckerImpl(policyService);
		AbacMethodSecurityExpressionRoot root =
			new AbacMethodSecurityExpressionRoot(new AbacAuththenticationWrapper(authentication), policyChecker);
		root.setPermissionEvaluator(getPermissionEvaluator());
		root.setTrustResolver(this.trustResolver);
		root.setRoleHierarchy(getRoleHierarchy());
		return root;
	}
}
