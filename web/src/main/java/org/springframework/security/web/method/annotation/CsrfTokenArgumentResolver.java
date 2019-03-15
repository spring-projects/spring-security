/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.method.annotation;

import org.springframework.core.MethodParameter;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.support.WebDataBinderFactory;
import org.springframework.web.context.request.NativeWebRequest;
import org.springframework.web.method.support.HandlerMethodArgumentResolver;
import org.springframework.web.method.support.ModelAndViewContainer;

/**
 * Allows resolving the current {@link CsrfToken}. For example, the following
 * {@link RestController} will resolve the current {@link CsrfToken}:
 *
 * <pre>
 * <code>
 * &#064;RestController
 * public class MyController {
 *     &#064;MessageMapping("/im")
 *     public CsrfToken csrf(CsrfToken token) {
 *         return token;
 *     }
 * }
 * </code>
 * </pre>
 *
 *
 * @author Rob Winch
 * @since 4.0
 */
public final class CsrfTokenArgumentResolver implements HandlerMethodArgumentResolver {

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.web.method.support.HandlerMethodArgumentResolver#supportsParameter
	 * (org.springframework.core.MethodParameter)
	 */
	public boolean supportsParameter(MethodParameter parameter) {
		return CsrfToken.class.equals(parameter.getParameterType());
	}

	/*
	 * (non-Javadoc)
	 *
	 * @see
	 * org.springframework.web.method.support.HandlerMethodArgumentResolver#resolveArgument
	 * (org.springframework.core.MethodParameter,
	 * org.springframework.web.method.support.ModelAndViewContainer,
	 * org.springframework.web.context.request.NativeWebRequest,
	 * org.springframework.web.bind.support.WebDataBinderFactory)
	 */
	public Object resolveArgument(MethodParameter parameter,
			ModelAndViewContainer mavContainer, NativeWebRequest webRequest,
			WebDataBinderFactory binderFactory) throws Exception {
		CsrfToken token = (CsrfToken) webRequest.getAttribute(CsrfToken.class.getName(),
				NativeWebRequest.SCOPE_REQUEST);
		return token;
	}
}