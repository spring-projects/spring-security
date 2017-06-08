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

import org.springframework.security.abac.model.PolicyChecker;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;

/**
 * @author Renato Soppelsa
 * @since 5.0
 */
public class AbacMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

	private PolicyChecker policyChecker;
	private Object filterObject;
	private Object returnObject;
	private Object target;

	/**
	 * This enables 'checkPolicy' to be evaluated in Pre- and Post Filters and Authorisations, just like 'hasRole'
	 * @param authentication Spring security Authentication
	 * @param policyChecker PolicyChecker implemenation
	 */
	public AbacMethodSecurityExpressionRoot(Authentication authentication, PolicyChecker policyChecker) {
		super(authentication);
		this.policyChecker = policyChecker;
	}

	/**
	 *
	 * @param targetDomainObject
	 * @param action
	 * @return
	 */
	public boolean checkPolicy(Object targetDomainObject, Object action) {
		return checkPolicy(targetDomainObject, action, null);
	}

	public boolean checkPolicy(Object action) {
		return checkPolicy(null, action, null);
	}

	public boolean checkPolicy() {
		return checkPolicy(null, null, null);
	}

	public boolean checkPolicy(Object targetDomainObject, Object action, Object environment) {
		return policyChecker.check(authentication, targetDomainObject, action, environment);
	}


	@Override
	public void setFilterObject(Object filterObject) {
		this.filterObject = filterObject;
	}

	@Override
	public Object getFilterObject() {
		return filterObject;
	}

	@Override
	public void setReturnObject(Object returnObject) {
		this.returnObject = returnObject;
	}

	@Override
	public Object getReturnObject() {
		return returnObject;
	}

	@Override
	public Object getThis() {
		return target;
	}

	void setThis(Object target) {
		this.target = target;
	}
}
