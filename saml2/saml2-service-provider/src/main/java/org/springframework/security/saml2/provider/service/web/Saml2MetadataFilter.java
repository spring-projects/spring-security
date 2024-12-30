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

package org.springframework.security.saml2.provider.service.web;

import java.io.IOException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.http.HttpHeaders;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponse;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponseResolver;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * A {@link jakarta.servlet.Filter} that returns the metadata for a Relying Party
 *
 * @author Jakub Kubrynski
 * @author Josh Cummings
 * @since 5.4
 */
public final class Saml2MetadataFilter extends OncePerRequestFilter {

	public static final String DEFAULT_METADATA_FILE_NAME = "saml-{registrationId}-metadata.xml";

	private final Saml2MetadataResponseResolver metadataResolver;

	public Saml2MetadataFilter(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver,
			Saml2MetadataResolver saml2MetadataResolver) {
		Assert.notNull(relyingPartyRegistrationResolver, "relyingPartyRegistrationResolver cannot be null");
		Assert.notNull(saml2MetadataResolver, "saml2MetadataResolver cannot be null");
		this.metadataResolver = new Saml2MetadataResponseResolverAdapter(relyingPartyRegistrationResolver,
				saml2MetadataResolver);
	}

	/**
	 * Constructs an instance of {@link Saml2MetadataFilter} using the provided
	 * parameters. The {@link #metadataResolver} field will be initialized with a
	 * {@link DefaultRelyingPartyRegistrationResolver} instance using the provided
	 * {@link RelyingPartyRegistrationRepository}
	 * @param relyingPartyRegistrationRepository the
	 * {@link RelyingPartyRegistrationRepository} to use
	 * @param saml2MetadataResolver the {@link Saml2MetadataResolver} to use
	 * @since 6.1
	 */
	public Saml2MetadataFilter(RelyingPartyRegistrationRepository relyingPartyRegistrationRepository,
			Saml2MetadataResolver saml2MetadataResolver) {
		this(new DefaultRelyingPartyRegistrationResolver(relyingPartyRegistrationRepository), saml2MetadataResolver);
	}

	/**
	 * Constructs an instance of {@link Saml2MetadataFilter}
	 * @param metadataResponseResolver the strategy for producing metadata
	 * @since 6.1
	 */
	public Saml2MetadataFilter(Saml2MetadataResponseResolver metadataResponseResolver) {
		this.metadataResolver = metadataResponseResolver;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
			throws ServletException, IOException {
		Saml2MetadataResponse metadata;
		try {
			metadata = this.metadataResolver.resolve(request);
		}
		catch (Saml2Exception ex) {
			response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
			return;
		}
		if (metadata == null) {
			chain.doFilter(request, response);
			return;
		}
		writeMetadataToResponse(response, metadata);
	}

	private void writeMetadataToResponse(HttpServletResponse response, Saml2MetadataResponse metadata)
			throws IOException {
		response.setContentType("application/samlmetadata+xml");
		String format = "attachment; filename=\"%s\"; filename*=UTF-8''%s";
		String fileName = metadata.getFileName();
		String encodedFileName = URLEncoder.encode(fileName, StandardCharsets.UTF_8);
		response.setHeader(HttpHeaders.CONTENT_DISPOSITION, String.format(format, fileName, encodedFileName));
		response.setContentLength(metadata.getMetadata().getBytes(StandardCharsets.UTF_8).length);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		response.getWriter().write(metadata.getMetadata());
	}

	/**
	 * Set the {@link RequestMatcher} that determines whether this filter should handle
	 * the incoming {@link HttpServletRequest}
	 * @param requestMatcher the {@link RequestMatcher} to identify requests for metadata
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be null");
		Assert.isInstanceOf(Saml2MetadataResponseResolverAdapter.class, this.metadataResolver,
				"a Saml2MetadataResponseResolver and RequestMatcher cannot be both set on this filter. Please set the request matcher on the Saml2MetadataResponseResolver itself.");
		((Saml2MetadataResponseResolverAdapter) this.metadataResolver).setRequestMatcher(requestMatcher);
	}

	/**
	 * Sets the metadata filename template containing the {@code {registrationId}}
	 * template variable.
	 *
	 * <p>
	 * The default value is {@code saml-{registrationId}-metadata.xml}
	 * @param metadataFilename metadata filename, must contain a {registrationId}
	 * @since 5.5
	 */
	public void setMetadataFilename(String metadataFilename) {
		Assert.hasText(metadataFilename, "metadataFilename cannot be empty");
		Assert.isTrue(metadataFilename.contains("{registrationId}"),
				"metadataFilename must contain a {registrationId} match variable");
		Assert.isInstanceOf(Saml2MetadataResponseResolverAdapter.class, this.metadataResolver,
				"a Saml2MetadataResponseResolver and file name cannot be both set on this filter. Please set the file name on the Saml2MetadataResponseResolver itself.");
		((Saml2MetadataResponseResolverAdapter) this.metadataResolver).setMetadataFilename(metadataFilename);
	}

	private static final class Saml2MetadataResponseResolverAdapter implements Saml2MetadataResponseResolver {

		private final RelyingPartyRegistrationResolver registrations;

		private RequestMatcher requestMatcher = new AntPathRequestMatcher(
				"/saml2/service-provider-metadata/{registrationId}");

		private final Saml2MetadataResolver metadataResolver;

		private String metadataFilename = DEFAULT_METADATA_FILE_NAME;

		Saml2MetadataResponseResolverAdapter(RelyingPartyRegistrationResolver registrations,
				Saml2MetadataResolver metadataResolver) {
			this.registrations = registrations;
			this.metadataResolver = metadataResolver;
		}

		@Override
		public Saml2MetadataResponse resolve(HttpServletRequest request) {
			RequestMatcher.MatchResult matcher = this.requestMatcher.matcher(request);
			if (!matcher.isMatch()) {
				return null;
			}
			String registrationId = matcher.getVariables().get("registrationId");
			RelyingPartyRegistration relyingPartyRegistration = this.registrations.resolve(request, registrationId);
			if (relyingPartyRegistration == null) {
				throw new Saml2Exception("registration not found");
			}
			registrationId = relyingPartyRegistration.getRegistrationId();
			String metadata = this.metadataResolver.resolve(relyingPartyRegistration);
			String fileName = this.metadataFilename.replace("{registrationId}", registrationId);
			return new Saml2MetadataResponse(metadata, fileName);
		}

		void setRequestMatcher(RequestMatcher requestMatcher) {
			Assert.notNull(requestMatcher, "requestMatcher cannot be null");
			this.requestMatcher = requestMatcher;
		}

		void setMetadataFilename(String metadataFilename) {
			Assert.hasText(metadataFilename, "metadataFilename cannot be empty");
			Assert.isTrue(metadataFilename.contains("{registrationId}"),
					"metadataFilename must contain a {registrationId} match variable");
			this.metadataFilename = metadataFilename;
		}

	}

}
