/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.oauth2.core.http.converter;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Map;

import org.springframework.core.ParameterizedTypeReference;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.util.Assert;

/**
 * A {@link HttpMessageConverter} for an {@link OidcUserInfo} created from an UserInfo
 * Endpoint Response.
 *
 * @author Joe Grandja
 * @author Christian Knoop
 * @since 5.6
 * @see AbstractHttpMessageConverter
 * @see OidcUserInfo
 */
public class OidcUserInfoHttpMessageConverter extends AbstractHttpMessageConverter<OidcUserInfo> {

	private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

	private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE = new ParameterizedTypeReference<Map<String, Object>>() {
	};

	private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters
			.getJsonMessageConverter();

	private Converter<Map<String, Object>, OidcUserInfo> userInfoResponseConverter = this::createUserInfo;

	private Converter<OidcUserInfo, Map<String, Object>> userInfoResponseParametersConverter = this::populateUserInfoResponseParameters;

	public OidcUserInfoHttpMessageConverter() {
		super(DEFAULT_CHARSET, MediaType.APPLICATION_JSON);
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
			Map<String, Object> claims = (Map<String, Object>) this.jsonMessageConverter
					.read(PARAMETERIZED_RESPONSE_TYPE.getType(), null, inputMessage);
			return this.userInfoResponseConverter.convert(claims);
		}
		catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the Userinfo Response: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OidcUserInfo oidcUserInfo, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {
		try {
			Map<String, Object> claims = this.userInfoResponseParametersConverter.convert(oidcUserInfo);
			this.jsonMessageConverter.write(claims, PARAMETERIZED_RESPONSE_TYPE.getType(), MediaType.APPLICATION_JSON,
					outputMessage);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the Userinfo Response: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the User Info Response parameters to
	 * an {@link OidcUserInfo}.
	 * @param userInfoResponseConverter the {@link Converter} used for converting to an
	 * {@link OidcUserInfo}
	 * @since 5.6
	 */
	public final void setUserInfoResponseConverter(
			Converter<Map<String, Object>, OidcUserInfo> userInfoResponseConverter) {
		Assert.notNull(userInfoResponseConverter, "userInfoResponseConverter cannot be null");
		this.userInfoResponseConverter = userInfoResponseConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OidcUserInfo} to a
	 * {@code Map} representation of the User Info Response parameters.
	 * @param userInfoResponseParametersConverter the {@link Converter} used for
	 * converting to a {@code Map} representation of the User Info Response parameters
	 * @since 5.6
	 */
	public final void setUserInfoResponseParametersConverter(
			Converter<OidcUserInfo, Map<String, Object>> userInfoResponseParametersConverter) {
		Assert.notNull(userInfoResponseParametersConverter, "userInfoResponseParametersConverter cannot be null");
		this.userInfoResponseParametersConverter = userInfoResponseParametersConverter;
	}

	private OidcUserInfo createUserInfo(Map<String, Object> claims) {
		return new OidcUserInfo(claims);
	}

	private Map<String, Object> populateUserInfoResponseParameters(OidcUserInfo oidcUserInfo) {
		return oidcUserInfo.getClaims();
	}

}
