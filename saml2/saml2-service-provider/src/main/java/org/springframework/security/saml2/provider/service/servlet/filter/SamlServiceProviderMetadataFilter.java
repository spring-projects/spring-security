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

package org.springframework.security.saml2.provider.service.servlet.filter;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

/**
 * This {@code Servlet} returns a generated Service Provider Metadata XML
 *
 * @since 5.4
 * @author Jakub Kubrynski
 */
public class SamlServiceProviderMetadataFilter extends OncePerRequestFilter {

	private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;
	private final SamlMetadataGenerator samlMetadataGenerator;

	private RequestMatcher redirectMatcher = new AntPathRequestMatcher("/saml2/service-provider-metadata/{registrationId}");

	public SamlServiceProviderMetadataFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {
		this(relyingPartyRegistrationRepository, new SamlMetadataGenerator());
	}

	SamlServiceProviderMetadataFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository, SamlMetadataGenerator samlMetadataGenerator) {
		this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
		this.samlMetadataGenerator = samlMetadataGenerator;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {

		RequestMatcher.MatchResult matcher = this.redirectMatcher.matcher(request);
		if (!matcher.isMatch()) {
			filterChain.doFilter(request, response);
			return;
		}

		String registrationId = matcher.getVariables().get("registrationId");

		RelyingPartyRegistration registration = relyingPartyRegistrationRepository.findByRegistrationId(registrationId);

		if (registration == null) {
			response.setStatus(404);
			return;
		}

		String xml = samlMetadataGenerator.generateMetadata(registration, request);

		writeMetadataToResponse(response, registrationId, xml);
	}

	private void writeMetadataToResponse(HttpServletResponse response, String registrationId, String xml) throws IOException {
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"saml-" + registrationId + "-metadata.xml\"");
		response.setContentLength(xml.length());
		ServletOutputStream outputStream = response.getOutputStream();
		outputStream.print(xml);
		outputStream.flush();
		outputStream.close();
	}

}
