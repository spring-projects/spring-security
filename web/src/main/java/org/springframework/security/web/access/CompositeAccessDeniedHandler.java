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

package org.springframework.security.web.access;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.access.AccessDeniedException;

public final class CompositeAccessDeniedHandler implements AccessDeniedHandler {

	private Collection<AccessDeniedHandler> handlers;

	public CompositeAccessDeniedHandler(AccessDeniedHandler... handlers) {
		this(Arrays.asList(handlers));
	}

	public CompositeAccessDeniedHandler(Collection<AccessDeniedHandler> handlers) {
		this.handlers = new ArrayList<>(handlers);
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response,
			AccessDeniedException accessDeniedException) throws IOException, ServletException {
		for (AccessDeniedHandler handler : this.handlers) {
			handler.handle(request, response, accessDeniedException);
		}
	}

}
