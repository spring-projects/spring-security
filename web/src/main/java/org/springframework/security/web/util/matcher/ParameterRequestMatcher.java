/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.web.util.matcher;

import java.util.Map;
import java.util.Objects;

import jakarta.servlet.http.HttpServletRequest;

/**
 * A {@link RequestMatcher} for matching on a request parameter and its value.
 *
 * <p>
 * The value may also be specified as a placeholder in order to match on any value,
 * returning the value as part of the {@link MatchResult}.
 *
 * @author Josh Cummings
 * @since 6.4
 */
public final class ParameterRequestMatcher implements RequestMatcher {

	private static final MatchesValueMatcher NON_NULL = Objects::nonNull;

	private final String name;

	private final ValueMatcher matcher;

	public ParameterRequestMatcher(String name) {
		this.name = name;
		this.matcher = NON_NULL;
	}

	public ParameterRequestMatcher(String name, String value) {
		this.name = name;
		MatchesValueMatcher matcher = value::equals;
		if (value.startsWith("{") && value.endsWith("}")) {
			String key = value.substring(1, value.length() - 1);
			this.matcher = (v) -> (v != null) ? MatchResult.match(Map.of(key, v)) : MatchResult.notMatch();
		}
		else {
			this.matcher = matcher;
		}
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return matcher(request).isMatch();
	}

	@Override
	public MatchResult matcher(HttpServletRequest request) {
		String parameterValue = request.getParameter(this.name);
		return this.matcher.matcher(parameterValue);
	}

	private interface ValueMatcher {

		MatchResult matcher(String value);

	}

	private interface MatchesValueMatcher extends ValueMatcher {

		default MatchResult matcher(String value) {
			if (matches(value)) {
				return MatchResult.match();
			}
			else {
				return MatchResult.notMatch();
			}
		}

		boolean matches(String value);

	}

}
