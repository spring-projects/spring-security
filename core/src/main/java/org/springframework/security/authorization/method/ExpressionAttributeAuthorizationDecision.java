/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.authorization.method;

import org.springframework.security.authorization.AuthorizationDecision;

/**
 * Represents an {@link AuthorizationDecision} based on a {@link ExpressionAttribute}
 *
 * @author Marcus Da Coregio
 * @since 5.6
 * @deprecated Use
 * {@link org.springframework.security.authorization.ExpressionAuthorizationDecision}
 * instead
 */
@Deprecated
public class ExpressionAttributeAuthorizationDecision extends AuthorizationDecision {

	private final ExpressionAttribute expressionAttribute;

	public ExpressionAttributeAuthorizationDecision(boolean granted, ExpressionAttribute expressionAttribute) {
		super(granted);
		this.expressionAttribute = expressionAttribute;
	}

	public ExpressionAttribute getExpressionAttribute() {
		return this.expressionAttribute;
	}

	@Override
	public String toString() {
		return getClass().getSimpleName() + " [" + "granted=" + isGranted() + ", expressionAttribute="
				+ this.expressionAttribute + ']';
	}

}
