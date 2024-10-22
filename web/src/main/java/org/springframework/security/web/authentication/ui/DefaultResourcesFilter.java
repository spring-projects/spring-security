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

package org.springframework.security.web.authentication.ui;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletRequest;
import jakarta.servlet.ServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

/**
 * Serve common static assets used in default UIs, such as CSS or Javascript files. For
 * internal use only.
 *
 * @author Daniel Garnier-Moiroux
 * @since 6.4
 */
public final class DefaultResourcesFilter extends GenericFilterBean {

	private final RequestMatcher matcher;

	private final ClassPathResource resource;

	private final MediaType mediaType;

	private DefaultResourcesFilter(RequestMatcher matcher, ClassPathResource resource, MediaType mediaType) {
		Assert.isTrue(resource.exists(), "classpath resource must exist");
		this.matcher = matcher;
		this.resource = resource;
		this.mediaType = mediaType;
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (!(request instanceof HttpServletRequest servletRequest)) {
			filterChain.doFilter(request, response);
			return;
		}

		if (this.matcher.matches(servletRequest)) {
			response.setContentType(this.mediaType.toString());
			response.getWriter().write(this.resource.getContentAsString(StandardCharsets.UTF_8));
			return;
		}

		filterChain.doFilter(request, response);
	}

	@Override
	public String toString() {
		return "%s [matcher=%s, resource=%s]".formatted(getClass().getSimpleName(), this.matcher.toString(),
				this.resource.getPath());
	}

	/**
	 * Create an instance of {@link DefaultResourcesFilter} serving Spring Security's
	 * default CSS stylesheet.
	 * <p>
	 * The created {@link DefaultResourcesFilter} matches requests
	 * {@code HTTP GET /default-ui.css}, and returns the default stylesheet at
	 * {@code org/springframework/security/default-ui.css} with content-type
	 * {@code text/css;charset=UTF-8}.
	 * @return -
	 */
	public static DefaultResourcesFilter css() {
		return new DefaultResourcesFilter(AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/default-ui.css"),
				new ClassPathResource("org/springframework/security/default-ui.css"),
				new MediaType("text", "css", StandardCharsets.UTF_8));
	}

	/**
	 * Create an instance of {@link DefaultResourcesFilter} serving Spring Security's
	 * default webauthn javascript.
	 * <p>
	 * The created {@link DefaultResourcesFilter} matches requests
	 * {@code HTTP GET /login/webauthn.js}, and returns the default webauthn javascript at
	 * {@code org/springframework/security/spring-security-webauthn.js} with content-type
	 * {@code text/javascript;charset=UTF-8}. This file is generated in the
	 * {@code spring-security-javascript} project.
	 * @return -
	 */
	public static DefaultResourcesFilter webauthn() {
		return new DefaultResourcesFilter(AntPathRequestMatcher.antMatcher(HttpMethod.GET, "/login/webauthn.js"),
				new ClassPathResource("org/springframework/security/spring-security-webauthn.js"),
				new MediaType("text", "javascript", StandardCharsets.UTF_8));
	}

}
