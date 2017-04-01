package org.springframework.security.abac;

import org.springframework.security.abac.model.PolicyChecker;
import org.springframework.security.access.expression.SecurityExpressionRoot;
import org.springframework.security.access.expression.method.MethodSecurityExpressionOperations;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.User;

public class AbacMethodSecurityExpressionRoot extends SecurityExpressionRoot implements MethodSecurityExpressionOperations {

	private PolicyChecker policyChecker;
	private Object filterObject;
	private Object returnObject;
	private Object target;

	public AbacMethodSecurityExpressionRoot(Authentication authentication, PolicyChecker policyChecker) {
		super(authentication);
		this.policyChecker = policyChecker;
	}

	public boolean ckeckPolicy(Object targetDomainObject, Object action) {
		return ckeckPolicy(targetDomainObject, action, null);
	}

	public boolean ckeckPolicy(Object targetDomainObject, Object action, Object environment) {
		return policyChecker.check(new AbacAuthenticationWrapper(authentication), targetDomainObject, action, environment);
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
