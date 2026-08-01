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

package org.springframework.security.oauth2.server.resource.web.server;

import java.util.Collections;
import java.util.Map;
import java.util.function.Consumer;

import org.jspecify.annotations.Nullable;
import reactor.core.publisher.Mono;

import org.springframework.core.ResolvableType;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.security.oauth2.server.resource.OAuth2ProtectedResourceMetadata;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import org.springframework.web.util.UriComponentsBuilder;

/**
 * A {@link WebFilter} that processes OAuth 2.0 Protected Resource Metadata Requests.
 *
 * @author Andrey Litvitski
 * @since 7.1
 * @see OAuth2ProtectedResourceMetadata
 * @see <a target="_blank" href=
 * "https://www.rfc-editor.org/rfc/rfc9728.html#section-3.1">3.1. Protected Resource
 * Metadata Request</a>
 */
public final class OAuth2ProtectedResourceMetadataWebFilter implements WebFilter {

	private static final ResolvableType STRING_OBJECT_MAP = ResolvableType.forClass(Map.class);

	/**
	 * The default endpoint {@code URI} for OAuth 2.0 Protected Resource Metadata
	 * requests.
	 */
	static final String DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI = "/.well-known/oauth-protected-resource";

	private final ServerWebExchangeMatcher requestMatcher = ServerWebExchangeMatchers.pathMatchers(HttpMethod.GET,
			DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI.concat("/**"));

	private final @Nullable HttpMessageWriter<Object> jsonMessageWriter = getJsonMessageWriter();

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
	public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
		return this.requestMatcher.matches(exchange).flatMap((matchResult) -> {
			if (!matchResult.isMatch()) {
				return chain.filter(exchange);
			}

			OAuth2ProtectedResourceMetadata.Builder builder = OAuth2ProtectedResourceMetadata.builder()
				.resource(resolveResourceIdentifier(exchange))
				.bearerMethod("header")
				.tlsClientCertificateBoundAccessTokens(true);

			this.protectedResourceMetadataCustomizer.accept(builder);

			OAuth2ProtectedResourceMetadata protectedResourceMetadata = builder.build();
			HttpMessageWriter<Object> jsonMessageWriter = this.jsonMessageWriter;
			Assert.state(jsonMessageWriter != null, "No JSON message writer available");
			exchange.getResponse().getHeaders().setContentType(MediaType.APPLICATION_JSON);
			return jsonMessageWriter.write(Mono.just(protectedResourceMetadata.getClaims()), STRING_OBJECT_MAP,
					STRING_OBJECT_MAP, MediaType.APPLICATION_JSON, exchange.getRequest(), exchange.getResponse(),
					Collections.emptyMap());
		});
	}

	private static String resolveResourceIdentifier(ServerWebExchange exchange) {
		// Resolve Resource Identifier dynamically from request
		String path = exchange.getRequest().getURI().getPath();
		if (!StringUtils.hasText(path)) {
			path = "";
		}
		else {
			path = path.replace(DEFAULT_OAUTH2_PROTECTED_RESOURCE_METADATA_ENDPOINT_URI, "");
		}

		// @formatter:off
		return UriComponentsBuilder.fromUri(exchange.getRequest().getURI())
				.replacePath(path)
				.replaceQuery(null)
				.fragment(null)
				.build()
				.toUriString();
		// @formatter:on
	}

	@SuppressWarnings("unchecked")
	private static @Nullable HttpMessageWriter<Object> getJsonMessageWriter() {
		return ServerCodecConfigurer.create()
			.getWriters()
			.stream()
			.filter((writer) -> writer.canWrite(STRING_OBJECT_MAP, MediaType.APPLICATION_JSON))
			.map((writer) -> (HttpMessageWriter<Object>) writer)
			.findFirst()
			.orElse(null);
	}

}
