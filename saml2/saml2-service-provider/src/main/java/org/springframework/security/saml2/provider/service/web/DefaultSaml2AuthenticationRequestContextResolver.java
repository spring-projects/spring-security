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

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequestContext;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import static org.springframework.security.web.util.UrlUtils.buildFullRequestUrl;
import static org.springframework.web.util.UriComponentsBuilder.fromHttpUrl;

/**
 * The default implementation for {@link Saml2AuthenticationRequestContextResolver}
 * which uses the current request and given relying party to formulate a {@link Saml2AuthenticationRequestContext}
 *
 * @author Shazin Sadakath
 * @since 5.4
 */
public final class DefaultSaml2AuthenticationRequestContextResolver implements Saml2AuthenticationRequestContextResolver {

	private final Log logger = LogFactory.getLog(getClass());

	private static final char PATH_DELIMITER = '/';

	/**
	 * {@inheritDoc}
	 */
	@Override
	public Saml2AuthenticationRequestContext resolve(HttpServletRequest request,
			RelyingPartyRegistration relyingParty) {
		Assert.notNull(request, "request cannot be null");
		Assert.notNull(relyingParty, "relyingParty cannot be null");
		if (this.logger.isDebugEnabled()) {
			this.logger.debug("Creating SAML 2.0 Authentication Request for Asserting Party [" +
					relyingParty.getRegistrationId() + "]");
		}
		return createRedirectAuthenticationRequestContext(request, relyingParty);
	}

	private Saml2AuthenticationRequestContext createRedirectAuthenticationRequestContext(
			HttpServletRequest request, RelyingPartyRegistration relyingParty) {

		String applicationUri = getApplicationUri(request);
		Function<String, String> resolver = templateResolver(applicationUri, relyingParty);
		String localSpEntityId = resolver.apply(relyingParty.getEntityId());
		String assertionConsumerServiceUrl = resolver.apply(relyingParty.getAssertionConsumerServiceLocation());
		return Saml2AuthenticationRequestContext.builder()
				.issuer(localSpEntityId)
				.relyingPartyRegistration(relyingParty)
				.assertionConsumerServiceUrl(assertionConsumerServiceUrl)
				.relayState(request.getParameter("RelayState"))
				.build();
	}

	private Function<String, String> templateResolver(String applicationUri, RelyingPartyRegistration relyingParty) {
		return template -> resolveUrlTemplate(template, applicationUri, relyingParty);
	}

	private static String resolveUrlTemplate(String template, String baseUrl, RelyingPartyRegistration relyingParty) {
		String entityId = relyingParty.getAssertingPartyDetails().getEntityId();
		String registrationId = relyingParty.getRegistrationId();
		Map<String, String> uriVariables = new HashMap<>();
		UriComponents uriComponents = UriComponentsBuilder.fromHttpUrl(baseUrl)
				.replaceQuery(null)
				.fragment(null)
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

		return UriComponentsBuilder.fromUriString(template)
				.buildAndExpand(uriVariables)
				.toUriString();
	}

	private static String getApplicationUri(HttpServletRequest request) {
		UriComponents uriComponents = fromHttpUrl(buildFullRequestUrl(request))
				.replacePath(request.getContextPath())
				.replaceQuery(null)
				.fragment(null)
				.build();
		return uriComponents.toUriString();
	}
}
