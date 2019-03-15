/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.web.authentication;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.WebAttributes;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.Assert;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * <p>
 * Forward Authentication Failure Handler
 * </p>
 *
 * @author Shazin Sadakath
 * @since 4.1
 */
public class ForwardAuthenticationFailureHandler implements AuthenticationFailureHandler {

	private final String forwardUrl;

	/**
	 * @param forwardUrl
	 */
	public ForwardAuthenticationFailureHandler(String forwardUrl) {
		Assert.isTrue(UrlUtils.isValidRedirectUrl(forwardUrl), "'"
				+ forwardUrl + "' is not a valid forward URL");
		this.forwardUrl = forwardUrl;
	}

	public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
		request.setAttribute(WebAttributes.AUTHENTICATION_EXCEPTION, exception);
		request.getRequestDispatcher(forwardUrl).forward(request, response);
	}
}
