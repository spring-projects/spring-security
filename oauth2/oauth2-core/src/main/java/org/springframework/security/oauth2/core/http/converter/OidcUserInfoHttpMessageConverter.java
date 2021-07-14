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
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.AbstractHttpMessageConverter;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;

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

	public OidcUserInfoHttpMessageConverter() {
		super(DEFAULT_CHARSET, MediaType.APPLICATION_JSON);
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OidcUserInfo.class.isAssignableFrom(clazz);
	}

	@Override
	protected OidcUserInfo readInternal(Class<? extends OidcUserInfo> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {
		try {
			Map<String, Object> claims = (Map<String, Object>) this.jsonMessageConverter
					.read(PARAMETERIZED_RESPONSE_TYPE.getType(), null, inputMessage);
			return new OidcUserInfo(claims);
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
			this.jsonMessageConverter.write(oidcUserInfo.getClaims(), PARAMETERIZED_RESPONSE_TYPE.getType(),
					MediaType.APPLICATION_JSON, outputMessage);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the Userinfo Response: " + ex.getMessage(), ex);
		}
	}

}
