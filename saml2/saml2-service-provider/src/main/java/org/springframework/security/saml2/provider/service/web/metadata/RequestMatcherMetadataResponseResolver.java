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

package org.springframework.security.saml2.provider.service.web.metadata;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResolver;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponse;
import org.springframework.security.saml2.provider.service.metadata.Saml2MetadataResponseResolver;
import org.springframework.security.saml2.provider.service.registration.IterableRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationPlaceholderResolvers;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.OrRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;

/**
 * An implementation of {@link Saml2MetadataResponseResolver} that identifies which
 * {@link RelyingPartyRegistration}s to use with a {@link RequestMatcher}
 *
 * @author Josh Cummings
 * @since 6.1
 */
public class RequestMatcherMetadataResponseResolver implements Saml2MetadataResponseResolver {

	private static final String DEFAULT_METADATA_FILENAME = "saml-{registrationId}-metadata.xml";

	private RequestMatcher matcher = new OrRequestMatcher(
			new AntPathRequestMatcher("/saml2/service-provider-metadata/{registrationId}"),
			new AntPathRequestMatcher("/saml2/metadata/{registrationId}"),
			new AntPathRequestMatcher("/saml2/metadata"));

	private String filename = DEFAULT_METADATA_FILENAME;

	private final RelyingPartyRegistrationRepository registrations;

	private final Saml2MetadataResolver metadata;

	/**
	 * Construct a
	 * {@link org.springframework.security.saml2.provider.service.metadata.RequestMatcherMetadataResponseResolver}
	 * @param registrations the source for relying party metadata
	 * @param metadata the strategy for converting {@link RelyingPartyRegistration}s into
	 * metadata
	 */
	public RequestMatcherMetadataResponseResolver(RelyingPartyRegistrationRepository registrations,
			Saml2MetadataResolver metadata) {
		Assert.notNull(registrations, "relyingPartyRegistrationRepository cannot be null");
		Assert.notNull(metadata, "saml2MetadataResolver cannot be null");
		this.registrations = registrations;
		this.metadata = metadata;
	}

	/**
	 * Construct and serialize a relying party's SAML 2.0 metadata based on the given
	 * {@link HttpServletRequest}. Uses the configured {@link RequestMatcher} to identify
	 * the metadata request, including looking for any indicated {@code registrationId}.
	 *
	 * <p>
	 * If a {@code registrationId} is found in the request, it will attempt to use that,
	 * erroring if no {@link RelyingPartyRegistration} is found.
	 *
	 * <p>
	 * If no {@code registrationId} is found in the request, it will attempt to show all
	 * {@link RelyingPartyRegistration}s in an {@code <md:EntitiesDescriptor>}. To
	 * exercise this functionality, the provided
	 * {@link RelyingPartyRegistrationRepository} needs to implement {@link Iterable}.
	 * @param request the HTTP request
	 * @return a {@link Saml2MetadataResponse} instance
	 * @throws Saml2Exception if the {@link RequestMatcher} specifies a non-existent
	 * {@code registrationId}
	 */
	@Override
	public Saml2MetadataResponse resolve(HttpServletRequest request) {
		RequestMatcher.MatchResult result = this.matcher.matcher(request);
		if (!result.isMatch()) {
			return null;
		}
		String registrationId = result.getVariables().get("registrationId");
		Saml2MetadataResponse response = responseByRegistrationId(request, registrationId);
		if (response != null) {
			return response;
		}
		if (this.registrations instanceof IterableRelyingPartyRegistrationRepository iterable) {
			return responseByIterable(request, iterable);
		}
		if (this.registrations instanceof Iterable<?>) {
			Iterable<RelyingPartyRegistration> registrations = (Iterable<RelyingPartyRegistration>) this.registrations;
			return responseByIterable(request, registrations);
		}
		return null;
	}

	private Saml2MetadataResponse responseByRegistrationId(HttpServletRequest request, String registrationId) {
		if (registrationId == null) {
			return null;
		}
		RelyingPartyRegistration registration = this.registrations.findByRegistrationId(registrationId);
		if (registration == null) {
			throw new Saml2Exception("registration not found");
		}
		return responseByIterable(request, Collections.singleton(registration));
	}

	private Saml2MetadataResponse responseByIterable(HttpServletRequest request,
			Iterable<RelyingPartyRegistration> registrations) {
		Map<String, RelyingPartyRegistration> results = new LinkedHashMap<>();
		for (RelyingPartyRegistration registration : registrations) {
			RelyingPartyRegistrationPlaceholderResolvers.UriResolver uriResolver = RelyingPartyRegistrationPlaceholderResolvers
				.uriResolver(request, registration);
			String entityId = uriResolver.resolve(registration.getEntityId());
			results.computeIfAbsent(entityId, (e) -> {
				String ssoLocation = uriResolver.resolve(registration.getAssertionConsumerServiceLocation());
				String sloLocation = uriResolver.resolve(registration.getSingleLogoutServiceLocation());
				String sloResponseLocation = uriResolver.resolve(registration.getSingleLogoutServiceResponseLocation());
				return registration.mutate()
					.entityId(entityId)
					.assertionConsumerServiceLocation(ssoLocation)
					.singleLogoutServiceLocation(sloLocation)
					.singleLogoutServiceResponseLocation(sloResponseLocation)
					.build();
			});
		}
		String metadata = this.metadata.resolve(results.values());
		String value = (results.size() == 1) ? results.values().iterator().next().getRegistrationId()
				: UUID.randomUUID().toString();
		String fileName = this.filename.replace("{registrationId}", value);
		try {
			String encodedFileName = URLEncoder.encode(fileName, StandardCharsets.UTF_8.name());
			return new Saml2MetadataResponse(metadata, encodedFileName);
		}
		catch (UnsupportedEncodingException ex) {
			throw new Saml2Exception(ex);
		}
	}

	/**
	 * Use this {@link RequestMatcher} to identity which requests to generate metadata
	 * for. By default, matches {@code /saml2/metadata},
	 * {@code /saml2/metadata/{registrationId}}, {@code /saml2/service-provider-metadata},
	 * and {@code /saml2/service-provider-metadata/{registrationId}}
	 * @param requestMatcher the {@link RequestMatcher} to use
	 */
	public void setRequestMatcher(RequestMatcher requestMatcher) {
		Assert.notNull(requestMatcher, "requestMatcher cannot be empty");
		this.matcher = requestMatcher;
	}

	/**
	 * Sets the metadata filename template. If it contains the {@code {registrationId}}
	 * placeholder, it will be resolved as a random UUID if there are multiple
	 * {@link RelyingPartyRegistration}s. Otherwise, it will be replaced by the
	 * {@link RelyingPartyRegistration}'s id.
	 *
	 * <p>
	 * The default value is {@code saml-{registrationId}-metadata.xml}
	 * @param metadataFilename metadata filename, must contain a {registrationId}
	 */
	public void setMetadataFilename(String metadataFilename) {
		Assert.hasText(metadataFilename, "metadataFilename cannot be empty");
		this.filename = metadataFilename;
	}

}
