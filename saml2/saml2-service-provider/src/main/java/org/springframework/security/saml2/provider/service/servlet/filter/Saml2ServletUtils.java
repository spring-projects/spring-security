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

import java.util.HashMap;
import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * @since 5.3
 */
final class Saml2ServletUtils {

	private static final char PATH_DELIMITER = '/';

	static String resolveUrlTemplate(String template, String baseUrl, RelyingPartyRegistration relyingParty) {
		if (!StringUtils.hasText(template)) {
			return baseUrl;
		}

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
		if (StringUtils.hasLength(path)) {
			if (path.charAt(0) != PATH_DELIMITER) {
				path = PATH_DELIMITER + path;
			}
		}
		uriVariables.put("basePath", path == null ? "" : path);
		uriVariables.put("baseUrl", uriComponents.toUriString());
		uriVariables.put("entityId", StringUtils.hasText(entityId) ? entityId : "");
		uriVariables.put("registrationId", StringUtils.hasText(registrationId) ? registrationId : "");

		return UriComponentsBuilder.fromUriString(template).buildAndExpand(uriVariables).toUriString();
	}

	static String getApplicationUri(HttpServletRequest request) {
		UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(UrlUtils.buildFullRequestUrl(request))
				.replacePath(request.getContextPath()).replaceQuery(null).fragment(null).build();
		return uriComponents.toUriString();
	}

}
