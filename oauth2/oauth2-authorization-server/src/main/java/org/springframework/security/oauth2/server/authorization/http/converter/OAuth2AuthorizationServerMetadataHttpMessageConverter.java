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

package org.springframework.security.oauth2.server.authorization.http.converter;

import java.net.URL;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadata;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationServerMetadataClaimNames;
import org.springframework.util.Assert;

/**
 * A {@link HttpMessageConverter} for an {@link OAuth2AuthorizationServerMetadata OAuth
 * 2.0 Authorization Server Metadata Response}.
 *
 * @author Daniel Garnier-Moiroux
 * @since 7.0
 * @see AbstractHttpMessageConverter
 * @see OAuth2AuthorizationServerMetadata
 */
public class OAuth2AuthorizationServerMetadataHttpMessageConverter
		extends AbstractHttpMessageConverter<OAuth2AuthorizationServerMetadata> {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters
		.getJsonMessageConverter();

	private Converter<Map<String, Object>, OAuth2AuthorizationServerMetadata> authorizationServerMetadataConverter = new OAuth2AuthorizationServerMetadataConverter();

	private Converter<OAuth2AuthorizationServerMetadata, Map<String, Object>> authorizationServerMetadataParametersConverter = OAuth2AuthorizationServerMetadata::getClaims;

	public OAuth2AuthorizationServerMetadataHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OAuth2AuthorizationServerMetadata.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OAuth2AuthorizationServerMetadata readInternal(Class<? extends OAuth2AuthorizationServerMetadata> clazz,
			HttpInputMessage inputMessage) throws HttpMessageNotReadableException {
		try {
			Map<String, Object> authorizationServerMetadataParameters = (Map<String, Object>) this.jsonMessageConverter
				.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.authorizationServerMetadataConverter.convert(authorizationServerMetadataParameters);
		}
		catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the OAuth 2.0 Authorization Server Metadata: " + ex.getMessage(), ex,
					inputMessage);
		}
	}

	@Override
	protected void writeInternal(OAuth2AuthorizationServerMetadata authorizationServerMetadata,
			HttpOutputMessage outputMessage) throws HttpMessageNotWritableException {
		try {
			Map<String, Object> authorizationServerMetadataResponseParameters = this.authorizationServerMetadataParametersConverter
				.convert(authorizationServerMetadata);
			this.jsonMessageConverter.write(authorizationServerMetadataResponseParameters, STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON, outputMessage);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the OAuth 2.0 Authorization Server Metadata: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the OAuth 2.0 Authorization Server
	 * Metadata parameters to an {@link OAuth2AuthorizationServerMetadata}.
	 * @param authorizationServerMetadataConverter the {@link Converter} used for
	 * converting to an {@link OAuth2AuthorizationServerMetadata}.
	 */
	public final void setAuthorizationServerMetadataConverter(
			Converter<Map<String, Object>, OAuth2AuthorizationServerMetadata> authorizationServerMetadataConverter) {
		Assert.notNull(authorizationServerMetadataConverter, "authorizationServerMetadataConverter cannot be null");
		this.authorizationServerMetadataConverter = authorizationServerMetadataConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the
	 * {@link OAuth2AuthorizationServerMetadata} to a {@code Map} representation of the
	 * OAuth 2.0 Authorization Server Metadata.
	 * @param authorizationServerMetadataParametersConverter the {@link Converter} used
	 * for converting to a {@code Map} representation of the OAuth 2.0 Authorization
	 * Server Metadata.
	 */
	public final void setAuthorizationServerMetadataParametersConverter(
			Converter<OAuth2AuthorizationServerMetadata, Map<String, Object>> authorizationServerMetadataParametersConverter) {
		Assert.notNull(authorizationServerMetadataParametersConverter,
				"authorizationServerMetadataParametersConverter cannot be null");
		this.authorizationServerMetadataParametersConverter = authorizationServerMetadataParametersConverter;
	}

	private static final class OAuth2AuthorizationServerMetadataConverter
			implements Converter<Map<String, Object>, OAuth2AuthorizationServerMetadata> {

		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService
			.getSharedInstance();

		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);

		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);

		private static final TypeDescriptor URL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(URL.class);

		private final ClaimTypeConverter claimTypeConverter;

		private OAuth2AuthorizationServerMetadataConverter() {
			Converter<Object, ?> collectionStringConverter = getConverter(
					TypeDescriptor.collection(Collection.class, STRING_TYPE_DESCRIPTOR));
			Converter<Object, ?> urlConverter = getConverter(URL_TYPE_DESCRIPTOR);

			Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.ISSUER, urlConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.AUTHORIZATION_ENDPOINT, urlConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.PUSHED_AUTHORIZATION_REQUEST_ENDPOINT,
					urlConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.DEVICE_AUTHORIZATION_ENDPOINT,
					urlConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT, urlConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHODS_SUPPORTED,
					collectionStringConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.JWKS_URI, urlConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.SCOPES_SUPPORTED,
					collectionStringConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.RESPONSE_TYPES_SUPPORTED,
					collectionStringConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.GRANT_TYPES_SUPPORTED,
					collectionStringConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT, urlConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.REVOCATION_ENDPOINT_AUTH_METHODS_SUPPORTED,
					collectionStringConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT, urlConverter);
			claimConverters.put(
					OAuth2AuthorizationServerMetadataClaimNames.INTROSPECTION_ENDPOINT_AUTH_METHODS_SUPPORTED,
					collectionStringConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.CODE_CHALLENGE_METHODS_SUPPORTED,
					collectionStringConverter);
			claimConverters.put(OAuth2AuthorizationServerMetadataClaimNames.DPOP_SIGNING_ALG_VALUES_SUPPORTED,
					collectionStringConverter);
			this.claimTypeConverter = new ClaimTypeConverter(claimConverters);
		}

		@Override
		public OAuth2AuthorizationServerMetadata convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
			return OAuth2AuthorizationServerMetadata.withClaims(parsedClaims).build();
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}

	}

}
