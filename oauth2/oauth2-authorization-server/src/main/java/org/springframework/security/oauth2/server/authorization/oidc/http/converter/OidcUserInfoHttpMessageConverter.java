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

package org.springframework.security.oauth2.server.authorization.oidc.http.converter;

import java.time.Instant;
import java.util.HashMap;
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
import org.springframework.security.oauth2.core.converter.ClaimConversionService;
import org.springframework.security.oauth2.core.converter.ClaimTypeConverter;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.util.Assert;

/**
 * A {@link HttpMessageConverter} for an {@link OidcUserInfo OpenID Connect UserInfo
 * Response}.
 *
 * @author Ido Salomon
 * @author Steve Riesenberg
 * @author Andrey Litvitski
 * @since 7.0
 * @see AbstractHttpMessageConverter
 * @see OidcUserInfo
 */
public class OidcUserInfoHttpMessageConverter extends AbstractHttpMessageConverter<OidcUserInfo> {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private final SmartHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters
		.getJsonMessageConverter();

	private Converter<Map<String, Object>, OidcUserInfo> userInfoConverter = new MapOidcUserInfoConverter();

	private Converter<OidcUserInfo, Map<String, Object>> userInfoParametersConverter = OidcUserInfo::getClaims;

	public OidcUserInfoHttpMessageConverter() {
		super(MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OidcUserInfo.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OidcUserInfo readInternal(Class<? extends OidcUserInfo> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {
		try {
			Map<String, Object> userInfoParameters = (Map<String, Object>) this.jsonMessageConverter
				.read(ResolvableType.forType(STRING_OBJECT_MAP.getType()), inputMessage, null);
			return this.userInfoConverter.convert(userInfoParameters);
		}
		catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the UserInfo response: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OidcUserInfo oidcUserInfo, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		try {
			Map<String, Object> userInfoResponseParameters = this.userInfoParametersConverter.convert(oidcUserInfo);
			this.jsonMessageConverter.write(userInfoResponseParameters,
					ResolvableType.forType(STRING_OBJECT_MAP.getType()), MediaType.APPLICATION_JSON, outputMessage,
					null);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the UserInfo response: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the UserInfo parameters to an
	 * {@link OidcUserInfo}.
	 * @param userInfoConverter the {@link Converter} used for converting to an
	 * {@link OidcUserInfo}
	 */
	public final void setUserInfoConverter(Converter<Map<String, Object>, OidcUserInfo> userInfoConverter) {
		Assert.notNull(userInfoConverter, "userInfoConverter cannot be null");
		this.userInfoConverter = userInfoConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OidcUserInfo} to a
	 * {@code Map} representation of the UserInfo.
	 * @param userInfoParametersConverter the {@link Converter} used for converting to a
	 * {@code Map} representation of the UserInfo
	 */
	public final void setUserInfoParametersConverter(
			Converter<OidcUserInfo, Map<String, Object>> userInfoParametersConverter) {
		Assert.notNull(userInfoParametersConverter, "userInfoParametersConverter cannot be null");
		this.userInfoParametersConverter = userInfoParametersConverter;
	}

	private static final class MapOidcUserInfoConverter implements Converter<Map<String, Object>, OidcUserInfo> {

		private static final ClaimConversionService CLAIM_CONVERSION_SERVICE = ClaimConversionService
			.getSharedInstance();

		private static final TypeDescriptor OBJECT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Object.class);

		private static final TypeDescriptor BOOLEAN_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Boolean.class);

		private static final TypeDescriptor STRING_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(String.class);

		private static final TypeDescriptor INSTANT_TYPE_DESCRIPTOR = TypeDescriptor.valueOf(Instant.class);

		private static final TypeDescriptor STRING_OBJECT_MAP_DESCRIPTOR = TypeDescriptor.map(Map.class,
				STRING_TYPE_DESCRIPTOR, OBJECT_TYPE_DESCRIPTOR);

		private final ClaimTypeConverter claimTypeConverter;

		private MapOidcUserInfoConverter() {
			Converter<Object, ?> booleanConverter = getConverter(BOOLEAN_TYPE_DESCRIPTOR);
			Converter<Object, ?> stringConverter = getConverter(STRING_TYPE_DESCRIPTOR);
			Converter<Object, ?> instantConverter = getConverter(INSTANT_TYPE_DESCRIPTOR);
			Converter<Object, ?> mapConverter = getConverter(STRING_OBJECT_MAP_DESCRIPTOR);

			Map<String, Converter<Object, ?>> claimConverters = new HashMap<>();
			claimConverters.put(StandardClaimNames.SUB, stringConverter);
			claimConverters.put(StandardClaimNames.NAME, stringConverter);
			claimConverters.put(StandardClaimNames.GIVEN_NAME, stringConverter);
			claimConverters.put(StandardClaimNames.FAMILY_NAME, stringConverter);
			claimConverters.put(StandardClaimNames.MIDDLE_NAME, stringConverter);
			claimConverters.put(StandardClaimNames.NICKNAME, stringConverter);
			claimConverters.put(StandardClaimNames.PREFERRED_USERNAME, stringConverter);
			claimConverters.put(StandardClaimNames.PROFILE, stringConverter);
			claimConverters.put(StandardClaimNames.PICTURE, stringConverter);
			claimConverters.put(StandardClaimNames.WEBSITE, stringConverter);
			claimConverters.put(StandardClaimNames.EMAIL, stringConverter);
			claimConverters.put(StandardClaimNames.EMAIL_VERIFIED, booleanConverter);
			claimConverters.put(StandardClaimNames.GENDER, stringConverter);
			claimConverters.put(StandardClaimNames.BIRTHDATE, stringConverter);
			claimConverters.put(StandardClaimNames.ZONEINFO, stringConverter);
			claimConverters.put(StandardClaimNames.LOCALE, stringConverter);
			claimConverters.put(StandardClaimNames.PHONE_NUMBER, stringConverter);
			claimConverters.put(StandardClaimNames.PHONE_NUMBER_VERIFIED, booleanConverter);
			claimConverters.put(StandardClaimNames.ADDRESS, mapConverter);
			claimConverters.put(StandardClaimNames.UPDATED_AT, instantConverter);

			this.claimTypeConverter = new ClaimTypeConverter(claimConverters);
		}

		@Override
		public OidcUserInfo convert(Map<String, Object> source) {
			Map<String, Object> parsedClaims = this.claimTypeConverter.convert(source);
			return new OidcUserInfo(parsedClaims);
		}

		private static Converter<Object, ?> getConverter(TypeDescriptor targetDescriptor) {
			return (source) -> CLAIM_CONVERSION_SERVICE.convert(source, OBJECT_TYPE_DESCRIPTOR, targetDescriptor);
		}

	}

}
