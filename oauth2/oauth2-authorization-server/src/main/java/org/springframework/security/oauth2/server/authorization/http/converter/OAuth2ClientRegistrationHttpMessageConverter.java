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
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
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
import org.springframework.security.oauth2.server.authorization.OAuth2ClientMetadataClaimNames;
import org.springframework.security.oauth2.server.authorization.OAuth2ClientRegistration;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * A {@link HttpMessageConverter} for an {@link OAuth2ClientRegistration OAuth 2.0 Dynamic
 * Client Registration Request and Response}.
 *
 * @author Joe Grandja
 * @since 7.0
 * @see AbstractHttpMessageConverter
 * @see OAuth2ClientRegistration
 */
public class OAuth2ClientRegistrationHttpMessageConverter
		extends AbstractHttpMessageConverter<OAuth2ClientRegistration> {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters
		.getJsonMessageConverter();

	private Converter<Map<String, Object>, OAuth2ClientRegistration> clientRegistrationConverter = new MapOAuth2ClientRegistrationConverter();

	private Converter<OAuth2ClientRegistration, Map<String, Object>> clientRegistrationParametersConverter = new OAuth2ClientRegistrationMapConverter();

	public OAuth2ClientRegistrationHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OAuth2ClientRegistration.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OAuth2ClientRegistration readInternal(Class<? extends OAuth2ClientRegistration> clazz,
			HttpInputMessage inputMessage) throws HttpMessageNotReadableException {
		try {
			Map<String, Object> clientRegistrationParameters = (Map<String, Object>) this.jsonMessageConverter
				.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.clientRegistrationConverter.convert(clientRegistrationParameters);
		}
		catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the OAuth 2.0 Client Registration: " + ex.getMessage(), ex,
					inputMessage);
		}
	}

	@Override
	protected void writeInternal(OAuth2ClientRegistration clientRegistration, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		try {
			Map<String, Object> clientRegistrationParameters = this.clientRegistrationParametersConverter
				.convert(clientRegistration);
			this.jsonMessageConverter.write(clientRegistrationParameters, STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON, outputMessage);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the OAuth 2.0 Client Registration: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the OAuth 2.0 Client Registration
	 * parameters to an {@link OAuth2ClientRegistration}.
	 * @param clientRegistrationConverter the {@link Converter} used for converting to an
	 * {@link OAuth2ClientRegistration}
	 */
	public final void setClientRegistrationConverter(
			Converter<Map<String, Object>, OAuth2ClientRegistration> clientRegistrationConverter) {
		Assert.notNull(clientRegistrationConverter, "clientRegistrationConverter cannot be null");
		this.clientRegistrationConverter = clientRegistrationConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OAuth2ClientRegistration}
	 * to a {@code Map} representation of the OAuth 2.0 Client Registration parameters.
	 * @param clientRegistrationParametersConverter the {@link Converter} used for
	 * converting to a {@code Map} representation of the OAuth 2.0 Client Registration
	 * parameters
	 */
	public final void setClientRegistrationParametersConverter(
			Converter<OAuth2ClientRegistration, Map<String, Object>> clientRegistrationParametersConverter) {
		Assert.notNull(clientRegistrationParametersConverter, "clientRegistrationParametersConverter cannot be null");
		this.clientRegistrationParametersConverter = clientRegistrationParametersConverter;
	}

	private static final class MapOAuth2ClientRegistrationConverter
			implements Converter<Map<String, Object>, OAuth2ClientRegistration> {

		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService
			.getSharedInstance();

		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);

		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);

		private static final TypeDescriptor INSTANT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Instant.class);

		private static final TypeDescriptor URL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(URL.class);

		private static final Converter<Object, ?> INSTANT_CONVERTER = getConverter(INSTANT_TYPE_DESCRIPTOR);

		private final ClaimTypeConverter claimTypeConverter;

		private MapOAuth2ClientRegistrationConverter() {
			Converter<Object, ?> stringConverter = getConverter(STRING_TYPE_DESCRIPTOR);
			Converter<Object, ?> collectionStringConverter = getConverter(
					TypeDescriptor.collection(Collection.class, STRING_TYPE_DESCRIPTOR));
			Converter<Object, ?> urlConverter = getConverter(URL_TYPE_DESCRIPTOR);

			Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
			claimConverters.put(OAuth2ClientMetadataClaimNames.CLIENT_ID, stringConverter);
			claimConverters.put(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT, INSTANT_CONVERTER);
			claimConverters.put(OAuth2ClientMetadataClaimNames.CLIENT_SECRET, stringConverter);
			claimConverters.put(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT,
					MapOAuth2ClientRegistrationConverter::convertClientSecretExpiresAt);
			claimConverters.put(OAuth2ClientMetadataClaimNames.CLIENT_NAME, stringConverter);
			claimConverters.put(OAuth2ClientMetadataClaimNames.REDIRECT_URIS, collectionStringConverter);
			claimConverters.put(OAuth2ClientMetadataClaimNames.TOKEN_ENDPOINT_AUTH_METHOD, stringConverter);
			claimConverters.put(OAuth2ClientMetadataClaimNames.GRANT_TYPES, collectionStringConverter);
			claimConverters.put(OAuth2ClientMetadataClaimNames.RESPONSE_TYPES, collectionStringConverter);
			claimConverters.put(OAuth2ClientMetadataClaimNames.SCOPE,
					MapOAuth2ClientRegistrationConverter::convertScope);
			claimConverters.put(OAuth2ClientMetadataClaimNames.JWKS_URI, urlConverter);
			this.claimTypeConverter = new ClaimTypeConverter(claimConverters);
		}

		@Override
		public OAuth2ClientRegistration convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
			Object clientSecretExpiresAt = parsedClaims.get(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT);
			if (clientSecretExpiresAt instanceof Number && clientSecretExpiresAt.equals(0)) {
				parsedClaims.remove(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT);
			}
			return OAuth2ClientRegistration.withClaims(parsedClaims).build();
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}

		private static Instant convertClientSecretExpiresAt(Object clientSecretExpiresAt) {
			if (clientSecretExpiresAt != null && String.valueOf(clientSecretExpiresAt).equals("0")) {
				// 0 indicates that client_secret_expires_at does not expire
				return null;
			}
			return (Instant) INSTANT_CONVERTER.convert(clientSecretExpiresAt);
		}

		private static List<String> convertScope(Object scope) {
			if (scope == null) {
				return Collections.emptyList();
			}
			return Arrays.asList(StringUtils.delimitedListToStringArray(scope.toString(), " "));
		}

	}

	private static final class OAuth2ClientRegistrationMapConverter
			implements Converter<OAuth2ClientRegistration, Map<String, Object>> {

		@Override
		public Map<String, Object> convert(OAuth2ClientRegistration source) {
			Map<String, Object> responseClaims = new LinkedHashMap<>(source.getClaims());
			if (source.getClientIdIssuedAt() != null) {
				responseClaims.put(OAuth2ClientMetadataClaimNames.CLIENT_ID_ISSUED_AT,
						source.getClientIdIssuedAt().getEpochSecond());
			}
			if (source.getClientSecret() != null) {
				long clientSecretExpiresAt = 0;
				if (source.getClientSecretExpiresAt() != null) {
					clientSecretExpiresAt = source.getClientSecretExpiresAt().getEpochSecond();
				}
				responseClaims.put(OAuth2ClientMetadataClaimNames.CLIENT_SECRET_EXPIRES_AT, clientSecretExpiresAt);
			}
			if (!CollectionUtils.isEmpty(source.getScopes())) {
				responseClaims.put(OAuth2ClientMetadataClaimNames.SCOPE,
						StringUtils.collectionToDelimitedString(source.getScopes(), " "));
			}
			return responseClaims;
		}

	}

}
