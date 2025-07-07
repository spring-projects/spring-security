/*
 * Copyright 2002-2025 the original author or authors.
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

package org.springframework.security.oauth2.client.userinfo;

import java.util.Map;

import org.springframework.context.expression.MapAccessor;
import org.springframework.expression.ExpressionParser;
import org.springframework.expression.spel.standard.SpelExpressionParser;
import org.springframework.expression.spel.support.SimpleEvaluationContext;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;

/**
 * Utility class for evaluating username expressions in OAuth2 user information.
 *
 * @author Yoobin Yoon
 * @since 7.0
 */
public final class OAuth2UsernameExpressionUtils {

	private static final String INVALID_USERNAME_EXPRESSION_ERROR_CODE = "invalid_username_expression";

	private static final String INVALID_USER_INFO_RESPONSE_ERROR_CODE = "invalid_user_info_response";

	private static final ExpressionParser expressionParser = new SpelExpressionParser();

	/**
	 * Evaluates a SpEL expression to extract the username from user attributes.
	 *
	 * <p>
	 * Examples:
	 * <ul>
	 * <li>Simple attribute: {@code "username"} or {@code "['username']"}</li>
	 * <li>Nested attribute: {@code "data.username"}</li>
	 * <li>Complex expression: {@code "user_info?.name ?: 'anonymous'"}</li>
	 * </ul>
	 * @param attributes the user attributes (used as SpEL root object)
	 * @param usernameExpression the SpEL expression to evaluate
	 * @return the evaluated username (never null)
	 * @throws OAuth2AuthenticationException if expression is invalid or evaluates to null
	 */
	public static String evaluateUsername(Map<String, Object> attributes, String usernameExpression) {
		Object value = null;

		try {
			SimpleEvaluationContext context = SimpleEvaluationContext.forPropertyAccessors(new MapAccessor())
				.withRootObject(attributes)
				.build();
			value = expressionParser.parseExpression(usernameExpression).getValue(context);
		}
		catch (Exception ex) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_USERNAME_EXPRESSION_ERROR_CODE,
					"Invalid username expression or SPEL expression: " + usernameExpression, null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString(), ex);
		}

		if (value == null) {
			OAuth2Error oauth2Error = new OAuth2Error(INVALID_USER_INFO_RESPONSE_ERROR_CODE,
					"An error occurred while attempting to retrieve the UserInfo Resource: username cannot be null",
					null);
			throw new OAuth2AuthenticationException(oauth2Error, oauth2Error.toString());
		}
		return value.toString();
	}

	private OAuth2UsernameExpressionUtils() {
	}

}
