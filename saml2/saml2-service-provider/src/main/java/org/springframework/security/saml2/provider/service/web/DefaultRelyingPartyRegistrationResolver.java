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

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.servlet.http.HttpServletRequest;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link Converter} that resolves a {@link RelyingPartyRegistration} by extracting the
 * registration id from the request, querying a
 * {@link RelyingPartyRegistrationRepository}, and resolving any template values.
 *
 * @author Josh Cummings
 * @since 5.4
 */
public final class DefaultRelyingPartyRegistrationResolver
		implements Converter<HttpServletRequest, RelyingPartyRegistration> {

	private static final char PATH_DELIMITER = '/';

	private final RelyingPartyRegistrationRepository relyingPartyRegistrationRepository;

	private final Converter<HttpServletRequest, String> registrationIdResolver = new RegistrationIdResolver();

	public DefaultRelyingPartyRegistrationResolver(
			RelyingPartyRegistrationRepository relyingPartyRegistrationRepository) {

		Assert.notNull(relyingPartyRegistrationRepository, "relyingPartyRegistrationRepository cannot be null");
		this.relyingPartyRegistrationRepository = relyingPartyRegistrationRepository;
	}

	@Override
	public RelyingPartyRegistration convert(HttpServletRequest request) {
		String registrationId = this.registrationIdResolver.convert(request);
		if (registrationId == null) {
			return null;
		}
		RelyingPartyRegistration relyingPartyRegistration = this.relyingPartyRegistrationRepository
				.findByRegistrationId(registrationId);
		if (relyingPartyRegistration == null) {
			return null;
		}

		String applicationUri = getApplicationUri(request);
		Function<String, String> templateResolver = templateResolver(applicationUri, relyingPartyRegistration);
		String relyingPartyEntityId = templateResolver.apply(relyingPartyRegistration.getEntityId());
		String assertionConsumerServiceLocation = templateResolver
				.apply(relyingPartyRegistration.getAssertionConsumerServiceLocation());
		return RelyingPartyRegistration.withRelyingPartyRegistration(relyingPartyRegistration)
				.entityId(relyingPartyEntityId).assertionConsumerServiceLocation(assertionConsumerServiceLocation)
				.build();
	}

	private Function<String, String> templateResolver(String applicationUri, RelyingPartyRegistration relyingParty) {
		return (template) -> resolveUrlTemplate(template, applicationUri, relyingParty);
	}

	private static String resolveUrlTemplate(String template, String baseUrl, RelyingPartyRegistration relyingParty) {
		String entityId = relyingParty.getAssertingPartyDetails().getEntityId();
		String registrationId = relyingParty.getRegistrationId();
		Map<String, String> uriVariables = new HashMap<>();
		UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(baseUrl).replaceQuery(null).fragment(null)
				.build();
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", scheme == null ? "" : scheme);
		String host = uriComponents.getHost();
		uriVariables.put("baseHost", host == null ? "" : host);
		// following logic is based on HierarchicalUriComponents#toUriString()
		int port = uriComponents.getPort();
		uriVariables.put("basePort", port == -1 ? "" : ":" + port);
		String path = uriComponents.getPath();
		if (StringUtils.hasLength(path) && path.charAt(0) != PATH_DELIMITER) {
			path = PATH_DELIMITER + path;
		}
		uriVariables.put("basePath", path == null ? "" : path);
		uriVariables.put("baseUrl", uriComponents.toUriString());
		uriVariables.put("entityId", StringUtils.hasText(entityId) ? entityId : "");
		uriVariables.put("registrationId", StringUtils.hasText(registrationId) ? registrationId : "");

		return UriComponentsBuilder.fromUriString(template).buildAndExpand(uriVariables).toUriString();
	}

	private static String getApplicationUri(HttpServletRequest request) {
		UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replacePath(request.getContextPath()).replaceQuery(null).fragment(null).build();
		return uriComponents.toUriString();
	}

	private static class RegistrationIdResolver implements Converter<HttpServletRequest, String> {

		private final RequestMatcher requestMatcher = new AntPathRequestMatcher("/**/{registrationId}");

		@Override
		public String convert(HttpServletRequest request) {
			RequestMatcher.MatchResult result = this.requestMatcher.matcher(request);
			return result.getVariables().get("registrationId");
		}

	}

}
