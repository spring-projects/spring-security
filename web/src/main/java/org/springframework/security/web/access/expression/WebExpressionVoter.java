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

package org.springframework.security.web.access.expression;

import java.util.Collection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.expression.EvaluationContext;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.expression.SecurityExpressionHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.FilterInvocation;
import org.springframework.util.Assert;

/**
 * Voter which handles web authorisation decisions.
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class WebExpressionVoter implements AccessDecisionVoter<FilterInvocation> {

	private final Log logger = LogFactory.getLog(getClass());

	private SecurityExpressionHandler<FilterInvocation> expressionHandler = new DefaultWebSecurityExpressionHandler();

	@Override
	public int vote(Authentication authentication, FilterInvocation filterInvocation,
			Collection<ConfigAttribute> attributes) {
		Assert.notNull(authentication, "authentication must not be null");
		Assert.notNull(filterInvocation, "filterInvocation must not be null");
		Assert.notNull(attributes, "attributes must not be null");
		WebExpressionConfigAttribute webExpressionConfigAttribute = findConfigAttribute(attributes);
		if (webExpressionConfigAttribute == null) {
			this.logger
					.trace("Abstained since did not find a config attribute of instance WebExpressionConfigAttribute");
			return ACCESS_ABSTAIN;
		}
		EvaluationContext ctx = webExpressionConfigAttribute.postProcess(
				this.expressionHandler.createEvaluationContext(authentication, filterInvocation), filterInvocation);
		boolean granted = ExpressionUtils.evaluateAsBoolean(webExpressionConfigAttribute.getAuthorizeExpression(), ctx);
		if (granted) {
			return ACCESS_GRANTED;
		}
		this.logger.trace("Voted to deny authorization");
		return ACCESS_DENIED;
	}

	private WebExpressionConfigAttribute findConfigAttribute(Collection<ConfigAttribute> attributes) {
		for (ConfigAttribute attribute : attributes) {
			if (attribute instanceof WebExpressionConfigAttribute) {
				return (WebExpressionConfigAttribute) attribute;
			}
		}
		return null;
	}

	@Override
	public boolean supports(ConfigAttribute attribute) {
		return attribute instanceof WebExpressionConfigAttribute;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

	public void setExpressionHandler(SecurityExpressionHandler<FilterInvocation> expressionHandler) {
		this.expressionHandler = expressionHandler;
	}

}
