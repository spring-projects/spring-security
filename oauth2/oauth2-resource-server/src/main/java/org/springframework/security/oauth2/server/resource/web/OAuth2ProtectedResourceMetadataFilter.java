/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.oauth2.server.resource.web;

import java.io.IOException;
import java.util.Map;
import java.util.function.Consumer;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.json.GsonHttpMessageConverter;
import org.springframework.http.converter.json.JsonbHttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadata;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.UrlUtils;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.util.Assert;
import org.springframework.util.ClassUtils;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@code Filter} that processes OAuth 2.0 Protected Resource Metadata Requests.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see OAuth2ProtectedResourceMetadata
 * @see <a target="_blank" href=
 * "https://www.rfc-editor.org/rfc/rfc9728.html#section-3.1">3.1. Protected Resource
 * Metadata Request</a>
 */
public final class OAuth2ProtectedResourceMetadataFilter extends OncePerRequestFilter {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private static final GenericHttpMessageConverter<Object> JSON_MESSAGE_CONVERTER = HttpMessageConverters
		.getJsonMessageConverter();

	/**
	 * The default endpoint {@code URI} for OAuth 2.0 Protected Resource Metadata
	 * requests.
	 */
	static final String DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI = "/.well-known/oauth-protected-resource";

	private final RequestMatcher requestMatcher = PathPatternRequestMatcher.withDefaults()
		.matcher(HttpMethod.GET, DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI.concat("/**"));

	private Consumer<OAuth2ProtectedResourceMetadata.Builder> protectedResourceMetadataCustomizer = (
			protectedResourceMetadata) -> {
	};

	/**
	 * Sets the {@code Consumer} providing access to the
	 * {@link OAuth2ProtectedResourceMetadata.Builder} allowing the ability to customize
	 * the claims of the Resource Server's configuration.
	 * @param protectedResourceMetadataCustomizer the {@code Consumer} providing access to
	 * the {@link OAuth2ProtectedResourceMetadata.Builder}
	 */
	public void setProtectedResourceMetadataCustomizer(
			Consumer<OAuth2ProtectedResourceMetadata.Builder> protectedResourceMetadataCustomizer) {
		Assert.notNull(protectedResourceMetadataCustomizer, "protectedResourceMetadataCustomizer cannot be null");
		this.protectedResourceMetadataCustomizer = protectedResourceMetadataCustomizer;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if (!this.requestMatcher.matches(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		OAuth2ProtectedResourceMetadata.Builder builder = OAuth2ProtectedResourceMetadata.builder()
			.resource(resolveResourceIdentifier(request))
			.bearerMethod("header")
			.tlsClientCertificateBoundAccessTokens(true);

		this.protectedResourceMetadataCustomizer.accept(builder);

		OAuth2ProtectedResourceMetadata protectedResourceMetadata = builder.build();

		try {
			ServletServerHttpResponse httpResponse = new ServletServerHttpResponse(response);
			JSON_MESSAGE_CONVERTER.write(protectedResourceMetadata.getClaims(), STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON, httpResponse);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the OAuth 2.0 Protected Resource Metadata: " + ex.getMessage(), ex);
		}
	}

	private static String resolveResourceIdentifier(HttpServletRequest request) {
		// Resolve Resource Identifier dynamically from request
		String path = request.getRequestURI();
		if (!StringUtils.hasText(path)) {
			path = "";
		}
		else {
			path = path.replace(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI, "");
		}

		// @formatter:off
		return UriComponentsBuilder.fromUriString(UrlUtils.buildFullRequestUrl(request))
				.replacePath(path)
				.replaceQuery(null)
				.fragment(null)
				.build()
				.toUriString();
		// @formatter:on
	}

	private static final class HttpMessageConverters {

		private static final boolean jackson2Present;

		private static final boolean gsonPresent;

		private static final boolean jsonbPresent;

		static {
			ClassLoader classLoader = HttpMessageConverters.class.getClassLoader();
			jackson2Present = ClassUtils.isPresent("com.fasterxml.jackson.databind.ObjectMapper", classLoader)
					&& ClassUtils.isPresent("com.fasterxml.jackson.core.JsonGenerator", classLoader);
			gsonPresent = ClassUtils.isPresent("com.google.gson.Gson", classLoader);
			jsonbPresent = ClassUtils.isPresent("jakarta.json.bind.Jsonb", classLoader);
		}

		private HttpMessageConverters() {
		}

		private static GenericHttpMessageConverter<Object> getJsonMessageConverter() {
			if (jackson2Present) {
				return new MappingJackson2HttpMessageConverter();
			}
			if (gsonPresent) {
				return new GsonHttpMessageConverter();
			}
			if (jsonbPresent) {
				return new JsonbHttpMessageConverter();
			}
			return null;
		}

	}

}
