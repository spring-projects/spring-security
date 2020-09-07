/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.web.access.intercept;

import java.util.Collections;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

/**
 * An {@link HttpServletRequest} authorization context.
 *
 * @author Evgeniy Cheban
 */
public final class RequestAuthorizationContext {

	private final HttpServletRequest request;

	private final Map<String, String> variables;

	/**
	 * Creates an instance.
	 * @param request the {@link HttpServletRequest} to use
	 */
	public RequestAuthorizationContext(HttpServletRequest request) {
		this(request, Collections.emptyMap());
	}

	/**
	 * Creates an instance.
	 * @param request the {@link HttpServletRequest} to use
	 * @param variables a map containing key-value pairs representing extracted variable
	 * names and variable values
	 */
	public RequestAuthorizationContext(HttpServletRequest request, Map<String, String> variables) {
		this.request = request;
		this.variables = variables;
	}

	/**
	 * Returns the {@link HttpServletRequest}.
	 * @return the {@link HttpServletRequest} to use
	 */
	public HttpServletRequest getRequest() {
		return this.request;
	}

	/**
	 * Returns the extracted variable values where the key is the variable name and the
	 * value is the variable value.
	 * @return a map containing key-value pairs representing extracted variable names and
	 * variable values
	 */
	public Map<String, String> getVariables() {
		return this.variables;
	}

}
