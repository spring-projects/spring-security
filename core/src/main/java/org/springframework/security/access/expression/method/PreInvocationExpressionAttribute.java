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

package org.springframework.security.access.expression.method;

import org.springframework.expression.Expression;
import org.springframework.expression.ParseException;
import org.springframework.security.access.prepost.PreInvocationAttribute;

/**
 * @author Luke Taylor
 * @since 3.0
 */
public class PreInvocationExpressionAttribute extends AbstractExpressionBasedMethodConfigAttribute
		implements PreInvocationAttribute {

	private final String filterTarget;

	PreInvocationExpressionAttribute(String filterExpression, String filterTarget, String authorizeExpression)
			throws ParseException {
		super(filterExpression, authorizeExpression);
		this.filterTarget = filterTarget;
	}

	PreInvocationExpressionAttribute(Expression filterExpression, String filterTarget, Expression authorizeExpression)
			throws ParseException {
		super(filterExpression, authorizeExpression);
		this.filterTarget = filterTarget;
	}

	/**
	 * The parameter name of the target argument (must be a Collection) to which filtering
	 * will be applied.
	 * @return the method parameter name
	 */
	String getFilterTarget() {
		return this.filterTarget;
	}

	@Override
	public String toString() {
		StringBuilder sb = new StringBuilder();
		Expression authorize = getAuthorizeExpression();
		Expression filter = getFilterExpression();
		sb.append("[authorize: '").append((authorize != null) ? authorize.getExpressionString() : "null");
		sb.append("', filter: '").append((filter != null) ? filter.getExpressionString() : "null");
		sb.append("', filterTarget: '").append(this.filterTarget).append("']");
		return sb.toString();
	}

}
