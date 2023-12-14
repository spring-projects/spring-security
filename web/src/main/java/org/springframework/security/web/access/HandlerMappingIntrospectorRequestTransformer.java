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

package org.springframework.security.web.access;

import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.Map;

import jakarta.servlet.DispatcherType;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;

import org.springframework.util.Assert;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

/**
 * Transforms by passing it into
 * {@link HandlerMappingIntrospector#setCache(HttpServletRequest)}. Before, it wraps the
 * {@link HttpServletRequest} to ensure that the methods needed work since some methods by
 * default throw {@link UnsupportedOperationException}.
 *
 * @author Rob Winch
 */
public class HandlerMappingIntrospectorRequestTransformer
		implements AuthorizationManagerWebInvocationPrivilegeEvaluator.HttpServletRequestTransformer {

	private final HandlerMappingIntrospector introspector;

	public HandlerMappingIntrospectorRequestTransformer(HandlerMappingIntrospector introspector) {
		Assert.notNull(introspector, "introspector canot be null");
		this.introspector = introspector;
	}

	@Override
	public HttpServletRequest transform(HttpServletRequest request) {
		CacheableRequestWrapper cacheableRequest = new CacheableRequestWrapper(request);
		this.introspector.setCache(cacheableRequest);
		return cacheableRequest;
	}

	static final class CacheableRequestWrapper extends HttpServletRequestWrapper {

		private final Map<String, Object> attributes = new HashMap<>();

		/**
		 * Constructs a request object wrapping the given request.
		 * @param request the {@link HttpServletRequest} to be wrapped.
		 * @throws IllegalArgumentException if the request is null
		 */
		CacheableRequestWrapper(HttpServletRequest request) {
			super(request);
		}

		@Override
		public DispatcherType getDispatcherType() {
			return DispatcherType.REQUEST;
		}

		@Override
		public Enumeration<String> getAttributeNames() {
			return Collections.enumeration(this.attributes.keySet());
		}

		@Override
		public Object getAttribute(String name) {
			return this.attributes.get(name);
		}

		@Override
		public void setAttribute(String name, Object o) {
			this.attributes.put(name, o);
		}

		@Override
		public void removeAttribute(String name) {
			this.attributes.remove(name);
		}

	}

}
