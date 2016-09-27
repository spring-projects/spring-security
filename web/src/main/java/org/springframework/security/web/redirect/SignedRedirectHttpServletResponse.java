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
import java.util.Set;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;

import org.springframework.util.StringUtils;

/**
 * A HttpServletResponseWrapper to validate redirect target URL with given
 * signature.
 * If the signature is invalid, an exception is thrown because the URL
 * might have been falsified.
 *
 * @author Takuya Iwatsuka
 */
public class SignedRedirectHttpServletResponse extends
		HttpServletResponseWrapper {

	private String sign;
	private SignCalculator signCalculator;
	private Set<String> excludedURLs;

	public SignedRedirectHttpServletResponse(HttpServletResponse response,
			String sign, SignCalculator signCalculator, Set<String> excludedURLs) {
		super(response);
		this.sign = sign;
		this.signCalculator = signCalculator;
		this.excludedURLs = excludedURLs;
	}

	@Override
	public void sendRedirect(String location) throws IOException {
		if (!excludedURLs.contains(location)) {
			if (!StringUtils.hasLength(sign)) {
				throw new InvalidRedirectException(
						"A signature for the url is missing.");
			} else if (!signCalculator.validateSign(location, sign)) {
				throw new InvalidRedirectException(
						"A signature for the url is invalid.");
			}
		}
		super.sendRedirect(location);
	}

}
