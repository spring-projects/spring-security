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

package org.springframework.security.access.prepost;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.framework.AopInfrastructureBean;
import org.springframework.security.core.Authentication;

/**
 * Performs argument filtering and authorization logic before a method is invoked.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public interface PreInvocationAuthorizationAdvice extends AopInfrastructureBean {

	/**
	 * The "before" advice which should be executed to perform any filtering necessary and
	 * to decide whether the method call is authorised.
	 * @param authentication the information on the principal on whose account the
	 * decision should be made
	 * @param mi the method invocation being attempted
	 * @param preInvocationAttribute the attribute built from the @PreFilter
	 * and @PostFilter annotations.
	 * @return true if authorised, false otherwise
	 */
	boolean before(Authentication authentication, MethodInvocation mi, PreInvocationAttribute preInvocationAttribute);

}
