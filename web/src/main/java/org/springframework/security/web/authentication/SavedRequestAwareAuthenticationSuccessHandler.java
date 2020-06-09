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

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.access.ExceptionTranslationFilter;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.util.StringUtils;

/**
 * An authentication success strategy which can make use of the
 * {@link org.springframework.security.web.savedrequest.DefaultSavedRequest} which may
 * have been stored in the session by the {@link ExceptionTranslationFilter}. When such a
 * request is intercepted and requires authentication, the request data is stored to
 * record the original destination before the authentication process commenced, and to
 * allow the request to be reconstructed when a redirect to the same URL occurs. This
 * class is responsible for performing the redirect to the original URL if appropriate.
 * <p>
 * Following a successful authentication, it decides on the redirect destination, based on
 * the following scenarios:
 * <ul>
 * <li>If the {@code alwaysUseDefaultTargetUrl} property is set to true, the
 * {@code defaultTargetUrl} will be used for the destination. Any
 * {@code DefaultSavedRequest} stored in the session will be removed.</li>
 * <li>If the {@code targetUrlParameter} has been set on the request, the value will be
 * used as the destination. Any {@code DefaultSavedRequest} will again be removed.</li>
 * <li>If a {@link org.springframework.security.web.savedrequest.SavedRequest} is found in
 * the {@code RequestCache} (as set by the {@link ExceptionTranslationFilter} to record
 * the original destination before the authentication process commenced), a redirect will
 * be performed to the Url of that original destination. The {@code SavedRequest} object
 * will remain cached and be picked up when the redirected request is received (See
 * <a href="
 * {@docRoot}/org/springframework/security/web/savedrequest/SavedRequestAwareWrapper.html">SavedRequestAwareWrapper</a>).
 * </li>
 * <li>If no {@link org.springframework.security.web.savedrequest.SavedRequest} is found,
 * it will delegate to the base class.</li>
 * </ul>
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class SavedRequestAwareAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

	protected final Log logger = LogFactory.getLog(this.getClass());

	private RequestCache requestCache = new HttpSessionRequestCache();

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws ServletException, IOException {
		SavedRequest savedRequest = this.requestCache.getRequest(request, response);
		if (savedRequest == null) {
			super.onAuthenticationSuccess(request, response, authentication);
			return;
		}
		String targetUrlParameter = getTargetUrlParameter();
		if (isAlwaysUseDefaultTargetUrl()
				|| (targetUrlParameter != null && StringUtils.hasText(request.getParameter(targetUrlParameter)))) {
			this.requestCache.removeRequest(request, response);
			super.onAuthenticationSuccess(request, response, authentication);
			return;
		}
		clearAuthenticationAttributes(request);
		// Use the DefaultSavedRequest URL
		String targetUrl = savedRequest.getRedirectUrl();
		getRedirectStrategy().sendRedirect(request, response, targetUrl);
	}

	public void setRequestCache(RequestCache requestCache) {
		this.requestCache = requestCache;
	}

}
