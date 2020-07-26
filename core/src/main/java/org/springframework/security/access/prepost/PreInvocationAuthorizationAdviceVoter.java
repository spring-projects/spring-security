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

import java.util.Collection;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.core.Authentication;

/**
 * Voter which performs the actions using a PreInvocationAuthorizationAdvice
 * implementation generated from @PreFilter and @PreAuthorize annotations.
 * <p>
 * In practice, if these annotations are being used, they will normally contain all the
 * necessary access control logic, so a voter-based system is not really necessary and a
 * single <tt>AccessDecisionManager</tt> which contained the same logic would suffice.
 * However, this class fits in readily with the traditional voter-based
 * <tt>AccessDecisionManager</tt> implementations used by Spring Security.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class PreInvocationAuthorizationAdviceVoter implements AccessDecisionVoter<MethodInvocation> {

	protected final Log logger = LogFactory.getLog(getClass());

	private final PreInvocationAuthorizationAdvice preAdvice;

	public PreInvocationAuthorizationAdviceVoter(PreInvocationAuthorizationAdvice pre) {
		this.preAdvice = pre;
	}

	public boolean supports(ConfigAttribute attribute) {
		return attribute instanceof PreInvocationAttribute;
	}

	public boolean supports(Class<?> clazz) {
		return MethodInvocation.class.isAssignableFrom(clazz);
	}

	public int vote(Authentication authentication, MethodInvocation method, Collection<ConfigAttribute> attributes) {

		// Find prefilter and preauth (or combined) attributes
		// if both null, abstain
		// else call advice with them

		PreInvocationAttribute preAttr = findPreInvocationAttribute(attributes);

		if (preAttr == null) {
			// No expression based metadata, so abstain
			return ACCESS_ABSTAIN;
		}

		boolean allowed = this.preAdvice.before(authentication, method, preAttr);

		return allowed ? ACCESS_GRANTED : ACCESS_DENIED;
	}

	private PreInvocationAttribute findPreInvocationAttribute(Collection<ConfigAttribute> config) {
		for (ConfigAttribute attribute : config) {
			if (attribute instanceof PreInvocationAttribute) {
				return (PreInvocationAttribute) attribute;
			}
		}

		return null;
	}

}
