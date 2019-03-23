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
 * Support class for {@link RequestPostProcessor}'s that establish a Spring Security context
 *
 * @author Rob Winch
 * @since 4.0
 */
public abstract class SecurityContextRequestPostProcessorSupport {

	public static SecurityContext
			createSecurityContext(final Authentication authentication, final HttpServletRequest request) {
		return save(authentication, request);
	}

	/**
	 * Saves the specified {@link Authentication} into an empty {@link SecurityContext} using the
	 * {@link SecurityContextRepository}.
	 *
	 * @param authentication the {@link Authentication} to save
	 * @param request the {@link HttpServletRequest} to use
	 */
	static SecurityContext save(final Authentication authentication, final HttpServletRequest request) {
		final SecurityContext securityContext = SecurityContextHolder.createEmptyContext();
		securityContext.setAuthentication(authentication);
		save(securityContext, request);
		return securityContext;
	}

	/**
	 * Saves the {@link SecurityContext} using the {@link SecurityContextRepository}
	 *
	 * @param securityContext the {@link SecurityContext} to save
	 * @param request the {@link HttpServletRequest} to use
	 */
	static void save(final SecurityContext securityContext, HttpServletRequest request) {
		SecurityContextRepository securityContextRepository = WebTestUtils.getSecurityContextRepository(request);
		final boolean isTestRepository =
				securityContextRepository instanceof SecurityContextRequestPostProcessorSupport.TestSecurityContextRepository;
		if (!isTestRepository) {
			securityContextRepository = new TestSecurityContextRepository(securityContextRepository);
			WebTestUtils.setSecurityContextRepository(request, securityContextRepository);
		}

		HttpServletResponse response = new MockHttpServletResponse();

		final HttpRequestResponseHolder requestResponseHolder = new HttpRequestResponseHolder(request, response);
		securityContextRepository.loadContext(requestResponseHolder);

		request = requestResponseHolder.getRequest();
		response = requestResponseHolder.getResponse();

		securityContextRepository.saveContext(securityContext, request, response);
	}

	/**
	 * Used to wrap the SecurityContextRepository to provide support for testing in stateless mode
	 */
	static class TestSecurityContextRepository implements SecurityContextRepository {
		private final static String ATTR_NAME =
				SecurityContextRequestPostProcessorSupport.TestSecurityContextRepository.class.getName()
						.concat(".REPO");

		private final SecurityContextRepository delegate;

		private TestSecurityContextRepository(final SecurityContextRepository delegate) {
			this.delegate = delegate;
		}

		@Override
		public SecurityContext loadContext(final HttpRequestResponseHolder requestResponseHolder) {
			final SecurityContext result = getContext(requestResponseHolder.getRequest());
			// always load from the delegate to ensure the request/response in the
			// holder are updated
			// remember the SecurityContextRepository is used in many different
			// locations
			final SecurityContext delegateResult = this.delegate.loadContext(requestResponseHolder);
			return result == null ? delegateResult : result;
		}

		@Override
		public void saveContext(
				final SecurityContext context,
				final HttpServletRequest request,
				final HttpServletResponse response) {
			request.setAttribute(ATTR_NAME, context);
			this.delegate.saveContext(context, request, response);
		}

		@Override
		public boolean containsContext(final HttpServletRequest request) {
			return getContext(request) != null || this.delegate.containsContext(request);
		}

		static SecurityContext getContext(final HttpServletRequest request) {
			return (SecurityContext) request.getAttribute(ATTR_NAME);
		}
	}
}