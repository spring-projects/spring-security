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

package org.springframework.security.web.authentication.ott;

import java.io.IOException;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.ott.OneTimeToken;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.util.Assert;

/**
 * A {@link OneTimeTokenGenerationSuccessHandler} that performs a redirect to a specific
 * location
 *
 * @author Marcus da Coregio
 * @since 6.4
 */
public final class RedirectOneTimeTokenGenerationSuccessHandler implements OneTimeTokenGenerationSuccessHandler {

	private final RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	private final String redirectUrl;

	/**
	 * Constructs an instance of this class that redirects to the specified URL.
	 * @param redirectUrl
	 */
	public RedirectOneTimeTokenGenerationSuccessHandler(String redirectUrl) {
		Assert.hasText(redirectUrl, "redirectUrl cannot be empty or null");
		this.redirectUrl = redirectUrl;
	}

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, OneTimeToken oneTimeToken)
			throws IOException {
		this.redirectStrategy.sendRedirect(request, response, this.redirectUrl);
	}

}
