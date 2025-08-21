/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.access;

import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import org.jspecify.annotations.Nullable;

import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.web.util.ServletRequestPathUtils;

/**
 * Prepares the privilege evaluator's request for {@link PathPatternRequestMatcher}
 * authorization rules.
 *
 * @author Josh Cummings
 * @since 6.5
 */
public final class PathPatternRequestTransformer
		implements AuthorizationManagerWebInvocationPrivilegeEvaluator.HttpServletRequestTransformer {

	@Override
	public HttpServletRequest transform(HttpServletRequest request) {
		HttpServletRequest wrapped = new AttributesSupportingHttpServletRequest(request);
		ServletRequestPathUtils.parseAndCache(wrapped);
		return wrapped;
	}

	private static final class AttributesSupportingHttpServletRequest extends HttpServletRequestWrapper {

		private final Map<String, Object> attributes = new HashMap<>();

		AttributesSupportingHttpServletRequest(HttpServletRequest request) {
			super(request);
		}

		@Override
		public @Nullable Object getAttribute(String name) {
			return this.attributes.get(name);
		}

		@Override
		public void setAttribute(String name, Object value) {
			this.attributes.put(name, value);
		}

		@Override
		public void removeAttribute(String name) {
			this.attributes.remove(name);
		}

	}

}
