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

package org.springframework.security.access.expression.method;

import org.aopalliance.intercept.MethodInvocation;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.log.LogMessage;
import org.springframework.expression.EvaluationContext;
import org.springframework.expression.Expression;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.expression.ExpressionUtils;
import org.springframework.security.access.prepost.PostInvocationAttribute;
import org.springframework.security.access.prepost.PostInvocationAuthorizationAdvice;
import org.springframework.security.core.Authentication;

/**
 * @author Luke Taylor
 * @since 3.0
 * @deprecated Use
 * {@link org.springframework.security.authorization.method.AuthorizationManagerAfterMethodInterceptor}
 * instead
 */
@Deprecated
public class ExpressionBasedPostInvocationAdvice implements PostInvocationAuthorizationAdvice {

	protected final Log logger = LogFactory.getLog(getClass());

	private final MethodSecurityExpressionHandler expressionHandler;

	public ExpressionBasedPostInvocationAdvice(MethodSecurityExpressionHandler expressionHandler) {
		this.expressionHandler = expressionHandler;
	}

	@Override
	public Object after(Authentication authentication, MethodInvocation mi, PostInvocationAttribute postAttr,
			Object returnedObject) throws AccessDeniedException {
		PostInvocationExpressionAttribute pia = (PostInvocationExpressionAttribute) postAttr;
		EvaluationContext ctx = this.expressionHandler.createEvaluationContext(authentication, mi);
		Expression postFilter = pia.getFilterExpression();
		Expression postAuthorize = pia.getAuthorizeExpression();
		if (postFilter != null) {
			this.logger.debug(LogMessage.format("Applying PostFilter expression %s", postFilter));
			if (returnedObject != null) {
				returnedObject = this.expressionHandler.filter(returnedObject, postFilter, ctx);
			}
			else {
				this.logger.debug("Return object is null, filtering will be skipped");
			}
		}
		this.expressionHandler.setReturnObject(returnedObject, ctx);
		if (postAuthorize != null && !ExpressionUtils.evaluateAsBoolean(postAuthorize, ctx)) {
			this.logger.debug("PostAuthorize expression rejected access");
			throw new AccessDeniedException("Access is denied");
		}
		return returnedObject;
	}

}
