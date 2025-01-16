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

package org.springframework.security.web.util.matcher;

import java.util.ArrayList;
import java.util.List;

import org.springframework.http.HttpMethod;

public interface RequestMatcherBuilder {

	default RequestMatcher[] pattern(HttpMethod method, String... patterns) {
		List<RequestMatcher> requestMatchers = new ArrayList<>();
		for (String pattern : patterns) {
			requestMatchers.add(pattern(method, pattern));
		}
		return requestMatchers.toArray(RequestMatcher[]::new);
	}

	default RequestMatcher[] pattern(String... patterns) {
		return pattern(null, patterns);
	}

	default RequestMatcher pattern(String pattern) {
		return pattern(null, pattern);
	}

	default RequestMatcher anyRequest() {
		return pattern(null, "/**");
	}

	RequestMatcher pattern(HttpMethod method, String pattern);

}
