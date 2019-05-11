/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.web.servlet.request;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.test.web.support.WebTestUtils;
import org.springframework.security.web.context.HttpRequestResponseHolder;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.test.web.servlet.request.RequestPostProcessor;

/**
 * Support class for {@link RequestPostProcessor}'s that establish a Spring Security
 * context
 */
public class SecurityContextRequestPostProcessorSupport {

	/**
	 * Saves the specified {@link Authentication} into an empty
	 * {@link SecurityContext} using the {@link SecurityContextRepository}.
	 *
	 * @param authentication the {@link Authentication} to save
	 * @param request the {@link HttpServletRequest} to use
	 */
	static final void save(Authentication authentication, HttpServletRequest request) {
		SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authentication);
		save(securityContext, request);
	}

	/**
	 * Saves the {@link SecurityContext} using the {@link SecurityContextRepository}
	 *
	 * @param securityContext the {@link SecurityContext} to save
	 * @param request the {@link HttpServletRequest} to use
	 */
	static final void save(SecurityContext securityContext, HttpServletRequest request) {
		SecurityContextRepository securityContextRepository = WebTestUtils
				.getSecurityContextRepository(request);
		boolean isTestRepository = securityContextRepository instanceof TestSecurityContextRepository;
		if (!isTestRepository) {
			securityContextRepository = new TestSecurityContextRepository(
					securityContextRepository);
			WebTestUtils.setSecurityContextRepository(request,
					securityContextRepository);
		}

		HttpServletResponse response = new MockHttpServletResponse();

		HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(
				request, response);
		securityContextRepository.loadContext(requestResponseHolder);

		request = requestResponseHolder.getRequest();
		response = requestResponseHolder.getResponse();

		securityContextRepository.saveContext(securityContext, request, response);
	}
}