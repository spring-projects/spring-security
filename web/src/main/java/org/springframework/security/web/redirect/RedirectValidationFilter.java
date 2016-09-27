/*
 * Copyright 2002-2016 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.security.web.redirect;

import java.io.IOException;
import java.util.Collections;
import java.util.Set;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * <p>
 * A servlet filter which provides <a href="https://www.owasp.org/index.php/Open_redirect">Open Redirect</a>
 * protection.
 * </p>
 *
 * <p>
 * When a redirect target URL is passed as a request parameter by specific
 * parameter name, this filter explore the signature of the URL for validation
 * from the request.
 * This filter wraps the request with {@link SignedRedirectHttpServletResponse}.
 * It validate the redirect target URL with the signature when a redirect occurs.
 * If you have to redirect to other URL than the one passed as the request
 * parameter, you can exclude the URL from the target of the validation.
 * </p>
 *
 * @author Takuya Iwatsuka
 */
public class RedirectValidationFilter extends OncePerRequestFilter {

	private String signParameter = "sign";

	private String redirectParameter = "redirectTo";

	private final SignCalculator signCalculator;

	private Set<String> excludedURLs = Collections.emptySet();

	/**
	 * Specifies a request parameter name to pass a signature for the redirect
	 * target URL. The default value is "sign".
	 *
	 * @param signParameter a parameter name for the signature
	 */
	public void setSignParameter(String signParameter) {
		Assert.hasLength(signParameter);
		this.signParameter = signParameter;
	}

	/**
	 * Specifies a parameter name to pass a redirect target URL. The default
	 * value is "redirectTo".
	 *
	 * @param redirectParameter a parameter name for the redirect target URL
	 */
	public void setRedirectParameter(String redirectParameter) {
		Assert.hasLength(redirectParameter);
		this.redirectParameter = redirectParameter;
	}

	/**
	 * @param signCalculator a {@link SingCalculator} which is used for actual validation
	 */
	public RedirectValidationFilter(SignCalculator signCalculator) {
		Assert.notNull(signCalculator, "signCalculator cannot be null");
		this.signCalculator = signCalculator;
	}

	/**
	 * @param excludedURLs a set of URLs which are not the target of the validation
	 */
	public void setExcludedURLs(Set<String> excludedURLs) {
		Assert.notNull(excludedURLs);
		this.excludedURLs = excludedURLs;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request,
			HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		request.setAttribute("_signParameter", signParameter);
		request.setAttribute("_redirectParameter", redirectParameter);
		request.setAttribute("_signCalculator", signCalculator);

		if (StringUtils.hasLength(request.getParameter(redirectParameter))) {
			String sign = request.getParameter(signParameter);
			HttpServletResponse signedResponse = new SignedRedirectHttpServletResponse(
					response, sign, signCalculator, excludedURLs);
			filterChain.doFilter(request, signedResponse);
		} else {
			filterChain.doFilter(request, response);
		}
	}

}