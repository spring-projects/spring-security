/*
 * Copyright 2002-2023 the original author or authors.
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

package org.springframework.security.config.annotation.web.configurers;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

final class ServletPatternRequestMatcher implements RequestMatcher {

	final String pattern;

	ServletPatternRequestMatcher(String pattern) {
		Assert.notNull(pattern, "pattern cannot be null");
		this.pattern = pattern;
	}

	@Override
	public boolean matches(HttpServletRequest request) {
		return this.pattern.equals(request.getHttpServletMapping().getPattern());
	}

	@Override
	public String toString() {
		return String.format("ServletPattern [pattern='%s']", this.pattern);
	}

}
