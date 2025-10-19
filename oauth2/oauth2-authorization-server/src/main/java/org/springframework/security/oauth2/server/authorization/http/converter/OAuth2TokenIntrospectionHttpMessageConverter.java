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
import org.springframework.core.ResolvableType;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.SmartHttpMessageConverter;
import org.springframework.security.oauth2.core.OAuth2TokenIntrospectionClaimNames;
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenIntrospection;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * A {@link HttpMessageConverter} for an {@link OAuth2TokenIntrospection OAuth 2.0 Token
 * Introspection Response}.
 *
 * @author Gerardo Roza
 * @author Joe Grandja
 * @author Andrey Litvitski
 * @since 7.0
 * @see AbstractHttpMessageConverter
 * @see OAuth2TokenIntrospection
 */
public class OAuth2TokenIntrospectionHttpMessageConverter
		extends AbstractHttpMessageConverter<OAuth2TokenIntrospection> {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private final SmartHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters
		.getJsonMessageConverter();

	private Converter<Map<String, Object>, OAuth2TokenIntrospection> tokenIntrospectionConverter = new MapOAuth2TokenIntrospectionConverter();

	private Converter<OAuth2TokenIntrospection, Map<String, Object>> tokenIntrospectionParametersConverter = new OAuth2TokenIntrospectionMapConverter();

	public OAuth2TokenIntrospectionHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OAuth2TokenIntrospection.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OAuth2TokenIntrospection readInternal(Class<? extends OAuth2TokenIntrospection> clazz,
			HttpInputMessage inputMessage) throws HttpMessageNotReadableException {
		try {
			Map<String, Object> tokenIntrospectionParameters = (Map<String, Object>) this.jsonMessageConverter
				.read(ResolvableType.forType(STRING_OBJECT_MAP.getType()), inputMessage, null);
			return this.tokenIntrospectionConverter.convert(tokenIntrospectionParameters);
		}
		catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the Token Introspection Response: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OAuth2TokenIntrospection tokenIntrospection, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		try {
			Map<String, Object> tokenIntrospectionResponseParameters = this.tokenIntrospectionParametersConverter
				.convert(tokenIntrospection);
			this.jsonMessageConverter.write(tokenIntrospectionResponseParameters,
					ResolvableType.forType(STRING_OBJECT_MAP.getType()), MediaType.APPLICATION_JSON, outputMessage,
					null);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the Token Introspection Response: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the Token Introspection Response
	 * parameters to an {@link OAuth2TokenIntrospection}.
	 * @param tokenIntrospectionConverter the {@link Converter} used for converting to an
	 * {@link OAuth2TokenIntrospection}
	 */
	public final void setTokenIntrospectionConverter(
			Converter<Map<String, Object>, OAuth2TokenIntrospection> tokenIntrospectionConverter) {
		Assert.notNull(tokenIntrospectionConverter, "tokenIntrospectionConverter cannot be null");
		this.tokenIntrospectionConverter = tokenIntrospectionConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting an {@link OAuth2TokenIntrospection}
	 * to a {@code Map} representation of the Token Introspection Response parameters.
	 * @param tokenIntrospectionParametersConverter the {@link Converter} used for
	 * converting to a {@code Map} representation of the Token Introspection Response
	 * parameters
	 */
	public final void setTokenIntrospectionParametersConverter(
			Converter<OAuth2TokenIntrospection, Map<String, Object>> tokenIntrospectionParametersConverter) {
		Assert.notNull(tokenIntrospectionParametersConverter, "tokenIntrospectionParametersConverter cannot be null");
		this.tokenIntrospectionParametersConverter = tokenIntrospectionParametersConverter;
	}

	private static final class MapOAuth2TokenIntrospectionConverter
			implements Converter<Map<String, Object>, OAuth2TokenIntrospection> {

		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService
			.getSharedInstance();

		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);

		private static final TypeDescriptor BOOLEAN_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Boolean.class);

		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);

		private static final TypeDescriptor INSTANT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Instant.class);

		private static final TypeDescriptor URL_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(URL.class);

		private final ClaimTypeConverter claimTypeConverter;

		private MapOAuth2TokenIntrospectionConverter() {
			Converter<Object, ?> booleanConverter = getConverter(BOOLEAN_TYPE_DESCRIPTOR);
			Converter<Object, ?> stringConverter = getConverter(STRING_TYPE_DESCRIPTOR);
			Converter<Object, ?> instantConverter = getConverter(INSTANT_TYPE_DESCRIPTOR);
			Converter<Object, ?> collectionStringConverter = getConverter(
					TypeDescriptor.collection(Collection.class, STRING_TYPE_DESCRIPTOR));
			Converter<Object, ?> urlConverter = getConverter(URL_TYPE_DESCRIPTOR);

			Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.ACTIVE, booleanConverter);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.SCOPE,
					MapOAuth2TokenIntrospectionConverter::convertScope);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.CLIENT_ID, stringConverter);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.USERNAME, stringConverter);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.TOKEN_TYPE, stringConverter);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.EXP, instantConverter);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.IAT, instantConverter);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.NBF, instantConverter);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.SUB, stringConverter);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.AUD, collectionStringConverter);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.ISS, urlConverter);
			claimConverters.put(OAuth2TokenIntrospectionClaimNames.JTI, stringConverter);
			this.claimTypeConverter = new ClaimTypeConverter(claimConverters);
		}

		@Override
		public OAuth2TokenIntrospection convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
			return OAuth2TokenIntrospection.withClaims(parsedClaims).build();
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}

		private static List<String> convertScope(Object scope) {
			if (scope == null) {
				return Collections.emptyList();
			}
			return Arrays.asList(StringUtils.delimitedListToStringArray(scope.toString(), " "));
		}

	}

	private static final class OAuth2TokenIntrospectionMapConverter
			implements Converter<OAuth2TokenIntrospection, Map<String, Object>> {

		@Override
		public Map<String, Object> convert(OAuth2TokenIntrospection source) {
			Map<String, Object> responseClaims = new LinkedHashMap<>(source.getClaims());
			if (!CollectionUtils.isEmpty(source.getScopes())) {
				responseClaims.put(OAuth2TokenIntrospectionClaimNames.SCOPE,
						StringUtils.collectionToDelimitedString(source.getScopes(), " "));
			}
			if (source.getExpiresAt() != null) {
				responseClaims.put(OAuth2TokenIntrospectionClaimNames.EXP, source.getExpiresAt().getEpochSecond());
			}
			if (source.getIssuedAt() != null) {
				responseClaims.put(OAuth2TokenIntrospectionClaimNames.IAT, source.getIssuedAt().getEpochSecond());
			}
			if (source.getNotBefore() != null) {
				responseClaims.put(OAuth2TokenIntrospectionClaimNames.NBF, source.getNotBefore().getEpochSecond());
			}
			return responseClaims;
		}

	}

}
