/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@link javax.servlet.Filter} that returns the metadata for a Relying Party
 *
 * @author Jakub Kubrynski
 * @author Josh Cummings
 * @since 5.4
 */
public final class Saml2MetadataFilter extends OncePerRequestFilter {

	private final Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationConverter;

	private final Saml2MetadataResolver saml2MetadataResolver;

	private RequestMatcher requestMatcher = new AntPathRequestMatcher(
			"/saml2/service-provider-metadata/{registrationId}");

	public Saml2MetadataFilter(
			Converter<HttpServletRequest, RelyingPartyRegistration> relyingPartyRegistrationConverter,
			Saml2MetadataResolver saml2MetadataResolver) {

		this.relyingPartyRegistrationConverter = relyingPartyRegistrationConverter;
		this.saml2MetadataResolver = saml2MetadataResolver;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {

		RequestMatcher.MatchResult matcher = this.requestMatcher.matcher(request);
		if (!matcher.isMatch()) {
			chain.doFilter(request, response);
			return;
		}

		RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationConverter.convert(request);
		if (relyingPartyRegistration == null) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}

		String metadata = this.saml2MetadataResolver.resolve(relyingPartyRegistration);
		String registrationId = relyingPartyRegistration.getRegistrationId();
		writeMetadataToResponse(response, registrationId, metadata);
	}

	private void writeMetadataToResponse(HttpServletResponse response, String registrationId, String metadata)
			throws IOException {

		response.setContentType(MediaType.APPLICATION_XML_VALUE);
		response.setHeader(HttpHeaders.CONTENT_DISPOSITION,
				"attachment; filename=\"saml-" + registrationId + "-metadata.xml\"");
		response.setContentLength(metadata.length());
		response.getWriter().write(metadata);
	}

	/**
	 * Set the {@link RequestMatcher} that determines whether this filter should handle
	 * the incoming {@link HttpServletRequest}
	 * @param requestMatcher
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		this.requestMatcher = requestMatcher;
	}

}
