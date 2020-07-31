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

package org.springframework.security.access.vote;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.util.Assert;

/**
 * Provides helper methods for writing domain object ACL voters. Not bound to any
 * particular ACL system.
 *
 * @author Ben Alex
 */
public abstract class AbstractAclVoter implements AccessDecisionVoter<MethodInvocation> {

	private Class<?> processDomainObjectClass;

	protected Object getDomainObjectInstance(MethodInvocation invocation) {
		Object[] args = invocation.getArguments();
		Class<?>[] params = invocation.getMethod().getParameterTypes();
		for (int i = 0; i < params.length; i++) {
			if (this.processDomainObjectClass.isAssignableFrom(params[i])) {
				return args[i];
			}
		}
		throw new AuthorizationServiceException("MethodInvocation: " + invocation
				+ " did not provide any argument of type: " + this.processDomainObjectClass);
	}

	public Class<?> getProcessDomainObjectClass() {
		return this.processDomainObjectClass;
	}

	public void setProcessDomainObjectClass(Class<?> processDomainObjectClass) {
		Assert.notNull(processDomainObjectClass, "processDomainObjectClass cannot be set to null");
		this.processDomainObjectClass = processDomainObjectClass;
	}

	/**
	 * This implementation supports only <code>MethodSecurityInterceptor</code>, because
	 * it queries the presented <code>MethodInvocation</code>.
	 * @param clazz the secure object
	 * @return <code>true</code> if the secure object is <code>MethodInvocation</code>,
	 * <code>false</code> otherwise
	 */
	@Override
	public boolean supports(Class<?> clazz) {
		return (MethodInvocation.class.isAssignableFrom(clazz));
	}

}
