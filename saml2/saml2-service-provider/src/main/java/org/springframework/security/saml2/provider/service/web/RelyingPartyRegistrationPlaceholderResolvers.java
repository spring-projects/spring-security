/*
 * Copyright 2002-2023 the original author or authors.
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

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A factory for creating placeholder resolvers for {@link RelyingPartyRegistration}
 * templates. Supports {@code baseUrl}, {@code baseScheme}, {@code baseHost},
 * {@code basePort}, {@code basePath}, {@code registrationId},
 * {@code relyingPartyEntityId}, and {@code assertingPartyEntityId}
 *
 * @author Josh Cummings
 * @since 6.1
 */
public final class RelyingPartyRegistrationPlaceholderResolvers {

	private static final char PATH_DELIMITER = '/';

	private RelyingPartyRegistrationPlaceholderResolvers() {

	}

	/**
	 * Create a resolver based on the given {@link HttpServletRequest}. Given the request,
	 * placeholders {@code baseUrl}, {@code baseScheme}, {@code baseHost},
	 * {@code basePort}, and {@code basePath} are resolved.
	 * @param request the HTTP request
	 * @return a resolver that can resolve {@code baseUrl}, {@code baseScheme},
	 * {@code baseHost}, {@code basePort}, and {@code basePath} placeholders
	 */
	public static UriResolver uriResolver(HttpServletRequest request) {
		return new UriResolver(uriVariables(request));
	}

	/**
	 * Create a resolver based on the given {@link HttpServletRequest}. Given the request,
	 * placeholders {@code baseUrl}, {@code baseScheme}, {@code baseHost},
	 * {@code basePort}, {@code basePath}, {@code registrationId},
	 * {@code assertingPartyEntityId}, and {@code relyingPartyEntityId} are resolved.
	 * @param request the HTTP request
	 * @return a resolver that can resolve {@code baseUrl}, {@code baseScheme},
	 * {@code baseHost}, {@code basePort}, {@code basePath}, {@code registrationId},
	 * {@code relyingPartyEntityId}, and {@code assertingPartyEntityId} placeholders
	 */
	public static UriResolver uriResolver(HttpServletRequest request, RelyingPartyRegistration registration) {
		String relyingPartyEntityId = registration.getEntityId();
		String assertingPartyEntityId = registration.getAssertingPartyMetadata().getEntityId();
		String registrationId = registration.getRegistrationId();
		Map<String, String> uriVariables = uriVariables(request);
		uriVariables.put("relyingPartyEntityId", StringUtils.hasText(relyingPartyEntityId) ? relyingPartyEntityId : "");
		uriVariables.put("assertingPartyEntityId",
				StringUtils.hasText(assertingPartyEntityId) ? assertingPartyEntityId : "");
		uriVariables.put("entityId", StringUtils.hasText(assertingPartyEntityId) ? assertingPartyEntityId : "");
		uriVariables.put("registrationId", StringUtils.hasText(registrationId) ? registrationId : "");
		return new UriResolver(uriVariables);
	}

	private static Map<String, String> uriVariables(HttpServletRequest request) {
		String baseUrl = getApplicationUri(request);
		Map<String, String> uriVariables = new HashMap<>();
		UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(baseUrl)
			.replaceQuery(null)
			.fragment(null)
			.build();
		String scheme = uriComponents.getScheme();
		uriVariables.put("baseScheme", (scheme != null) ? scheme : "");
		String host = uriComponents.getHost();
		uriVariables.put("baseHost", (host != null) ? host : "");
		// following logic is based on HierarchicalUriComponents#toUriString()
		int port = uriComponents.getPort();
		uriVariables.put("basePort", (port == -1) ? "" : ":" + port);
		String path = uriComponents.getPath();
		if (StringUtils.hasLength(path) && path.charAt(0) != PATH_DELIMITER) {
			path = PATH_DELIMITER + path;
		}
		uriVariables.put("basePath", (path != null) ? path : "");
		uriVariables.put("baseUrl", uriComponents.toUriString());
		return uriVariables;
	}

	private static String getApplicationUri(HttpServletRequest request) {
		UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
			.replacePath(request.getContextPath())
			.replaceQuery(null)
			.fragment(null)
			.build();
		return uriComponents.toUriString();
	}

	/**
	 * A class for resolving {@link RelyingPartyRegistration} URIs
	 */
	public static final class UriResolver {

		private final Map<String, String> uriVariables;

		private UriResolver(Map<String, String> uriVariables) {
			this.uriVariables = uriVariables;
		}

		public String resolve(String uri) {
			if (uri == null) {
				return null;
			}
			return UriComponentsBuilder.fromUriString(uri).buildAndExpand(this.uriVariables).toUriString();
		}

	}

}
