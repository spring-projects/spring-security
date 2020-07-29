/*
 * Copyright 2002-2014 the original author or authors.
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

package org.springframework.security.test.web.support;

import java.util.List;

import javax.servlet.Filter;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.NoSuchBeanDefinitionException;
import org.springframework.security.config.BeanIds;
import org.springframework.security.web.context.AbstractSecurityWebApplicationInitializer;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.context.SecurityContextRepository;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.csrf.CsrfTokenRepository;
import org.springframework.security.web.csrf.HttpSessionCsrfTokenRepository;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.support.WebApplicationContextUtils;

/**
 * A utility class for testing spring security
 *
 * @author Rob Winch
 * @since 4.0
 */
public abstract class WebTestUtils {

	private static final SecurityContextRepository DEFAULT_CONTEXT_REPO = new HttpSessionSecurityContextRepository();

	private static final CsrfTokenRepository DEFAULT_TOKEN_REPO = new HttpSessionCsrfTokenRepository();

	/**
	 * Gets the {@link SecurityContextRepository} for the specified
	 * {@link HttpServletRequest}. If one is not found, a default
	 * {@link HttpSessionSecurityContextRepository} is used.
	 * @param request the {@link HttpServletRequest} to obtain the
	 * {@link SecurityContextRepository}
	 * @return the {@link SecurityContextRepository} for the specified
	 * {@link HttpServletRequest}
	 */
	public static SecurityContextRepository getSecurityContextRepository(HttpServletRequest request) {
		SecurityContextPersistenceFilter filter = findFilter(request, SecurityContextPersistenceFilter.class);
		if (filter == null) {
			return DEFAULT_CONTEXT_REPO;
		}
		return (SecurityContextRepository) ReflectionTestUtils.getField(filter, "repo");
	}

	/**
	 * Sets the {@link SecurityContextRepository} for the specified
	 * {@link HttpServletRequest}.
	 * @param request the {@link HttpServletRequest} to obtain the
	 * {@link SecurityContextRepository}
	 * @param securityContextRepository the {@link SecurityContextRepository} to set
	 */
	public static void setSecurityContextRepository(HttpServletRequest request,
			SecurityContextRepository securityContextRepository) {
		SecurityContextPersistenceFilter filter = findFilter(request, SecurityContextPersistenceFilter.class);
		if (filter != null) {
			ReflectionTestUtils.setField(filter, "repo", securityContextRepository);
		}
	}

	/**
	 * Gets the {@link CsrfTokenRepository} for the specified {@link HttpServletRequest}.
	 * If one is not found, the default {@link HttpSessionCsrfTokenRepository} is used.
	 * @param request the {@link HttpServletRequest} to obtain the
	 * {@link CsrfTokenRepository}
	 * @return the {@link CsrfTokenRepository} for the specified
	 * {@link HttpServletRequest}
	 */
	public static CsrfTokenRepository getCsrfTokenRepository(HttpServletRequest request) {
		CsrfFilter filter = findFilter(request, CsrfFilter.class);
		if (filter == null) {
			return DEFAULT_TOKEN_REPO;
		}
		return (CsrfTokenRepository) ReflectionTestUtils.getField(filter, "tokenRepository");
	}

	/**
	 * Sets the {@link CsrfTokenRepository} for the specified {@link HttpServletRequest}.
	 * @param request the {@link HttpServletRequest} to obtain the
	 * {@link CsrfTokenRepository}
	 * @param repository the {@link CsrfTokenRepository} to set
	 */
	public static void setCsrfTokenRepository(HttpServletRequest request, CsrfTokenRepository repository) {
		CsrfFilter filter = findFilter(request, CsrfFilter.class);
		if (filter != null) {
			ReflectionTestUtils.setField(filter, "tokenRepository", repository);
		}
	}

	@SuppressWarnings("unchecked")
	static <T extends Filter> T findFilter(HttpServletRequest request, Class<T> filterClass) {
		ServletContext servletContext = request.getServletContext();
		Filter springSecurityFilterChain = getSpringSecurityFilterChain(servletContext);
		if (springSecurityFilterChain == null) {
			return null;
		}
		List<Filter> filters = ReflectionTestUtils.invokeMethod(springSecurityFilterChain, "getFilters", request);
		if (filters == null) {
			return null;
		}
		for (Filter filter : filters) {
			if (filterClass.isAssignableFrom(filter.getClass())) {
				return (T) filter;
			}
		}
		return null;
	}

	private static Filter getSpringSecurityFilterChain(ServletContext servletContext) {
		Filter result = (Filter) servletContext.getAttribute(BeanIds.SPRING_SECURITY_FILTER_CHAIN);
		if (result != null) {
			return result;
		}
		WebApplicationContext webApplicationContext = WebApplicationContextUtils
				.getWebApplicationContext(servletContext);
		if (webApplicationContext != null) {
			try {
				return webApplicationContext.getBean(AbstractSecurityWebApplicationInitializer.DEFAULT_FILTER_NAME,
						Filter.class);
			}
			catch (NoSuchBeanDefinitionException notFound) {
			}
		}
		return null;
	}

	private WebTestUtils() {
	}

}
