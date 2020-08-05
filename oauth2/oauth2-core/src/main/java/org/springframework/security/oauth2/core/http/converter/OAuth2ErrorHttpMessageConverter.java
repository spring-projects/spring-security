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
package org.springframework.security.oauth2.core.http.converter;

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
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * A {@link HttpMessageConverter} for an {@link OAuth2Error OAuth 2.0 Error}.
 *
 * @see AbstractHttpMessageConverter
 * @see OAuth2Error
 * @author Joe Grandja
 * @since 5.1
 */
public class OAuth2ErrorHttpMessageConverter extends AbstractHttpMessageConverter<OAuth2Error> {

	private static final Charset DEFAULT_CHARSET = StandardCharsets.UTF_8;

	private static final ParameterizedTypeReference<Map<String, Object>> PARAMETERIZED_RESPONSE_TYPE = new ParameterizedTypeReference<Map<String, Object>>() {
	};

	private GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters.getJsonMessageConverter();

	protected Converter<Map<String, String>, OAuth2Error> errorConverter = new OAuth2ErrorConverter();

	protected Converter<OAuth2Error, Map<String, String>> errorParametersConverter = new OAuth2ErrorParametersConverter();

	public OAuth2ErrorHttpMessageConverter() {
		super(DEFAULT_CHARSET, MediaType.APPLICATION_JSON, new MediaType("application", "*+json"));
	}

	@Override
	protected boolean supports(Class<?> clazz) {
		return OAuth2Error.class.isAssignableFrom(clazz);
	}

	@Override
	protected OAuth2Error readInternal(Class<? extends OAuth2Error> clazz, HttpInputMessage inputMessage)
			throws HttpMessageNotReadableException {

		try {
			// gh-8157
			// Parse parameter values as Object in order to handle potential JSON Object
			// and then convert values to String
			@SuppressWarnings("unchecked")
			Map<String, Object> errorParameters = (Map<String, Object>) this.jsonMessageConverter
					.read(PARAMETERIZED_RESPONSE_TYPE.getType(), null, inputMessage);
			return this.errorConverter.convert(errorParameters.entrySet().stream()
					.collect(Collectors.toMap(Map.Entry::getKey, entry -> String.valueOf(entry.getValue()))));
		}
		catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the OAuth 2.0 Error: " + ex.getMessage(), ex, inputMessage);
		}
	}

	@Override
	protected void writeInternal(OAuth2Error oauth2Error, HttpOutputMessage outputMessage)
			throws HttpMessageNotWritableException {

		try {
			Map<String, String> errorParameters = this.errorParametersConverter.convert(oauth2Error);
			this.jsonMessageConverter.write(errorParameters, PARAMETERIZED_RESPONSE_TYPE.getType(),
					MediaType.APPLICATION_JSON, outputMessage);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the OAuth 2.0 Error: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the OAuth 2.0 Error parameters to an
	 * {@link OAuth2Error}.
	 * @param errorConverter the {@link Converter} used for converting to an
	 * {@link OAuth2Error}
	 */
	public final void setErrorConverter(Converter<Map<String, String>, OAuth2Error> errorConverter) {
		Assert.notNull(errorConverter, "errorConverter cannot be null");
		this.errorConverter = errorConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the {@link OAuth2Error} to a
	 * {@code Map} representation of the OAuth 2.0 Error parameters.
	 * @param errorParametersConverter the {@link Converter} used for converting to a
	 * {@code Map} representation of the Error parameters
	 */
	public final void setErrorParametersConverter(
			Converter<OAuth2Error, Map<String, String>> errorParametersConverter) {
		Assert.notNull(errorParametersConverter, "errorParametersConverter cannot be null");
		this.errorParametersConverter = errorParametersConverter;
	}

	/**
	 * A {@link Converter} that converts the provided OAuth 2.0 Error parameters to an
	 * {@link OAuth2Error}.
	 */
	private static class OAuth2ErrorConverter implements Converter<Map<String, String>, OAuth2Error> {

		@Override
		public OAuth2Error convert(Map<String, String> parameters) {
			String errorCode = parameters.get(OAuth2ParameterNames.ERROR);
			String errorDescription = parameters.get(OAuth2ParameterNames.ERROR_DESCRIPTION);
			String errorUri = parameters.get(OAuth2ParameterNames.ERROR_URI);

			return new OAuth2Error(errorCode, errorDescription, errorUri);
		}

	}

	/**
	 * A {@link Converter} that converts the provided {@link OAuth2Error} to a {@code Map}
	 * representation of OAuth 2.0 Error parameters.
	 */
	private static class OAuth2ErrorParametersConverter implements Converter<OAuth2Error, Map<String, String>> {

		@Override
		public Map<String, String> convert(OAuth2Error oauth2Error) {
			Map<String, String> parameters = new HashMap<>();

			parameters.put(OAuth2ParameterNames.ERROR, oauth2Error.getErrorCode());
			if (StringUtils.hasText(oauth2Error.getDescription())) {
				parameters.put(OAuth2ParameterNames.ERROR_DESCRIPTION, oauth2Error.getDescription());
			}
			if (StringUtils.hasText(oauth2Error.getUri())) {
				parameters.put(OAuth2ParameterNames.ERROR_URI, oauth2Error.getUri());
			}

			return parameters;
		}

	}

}
