/*
 * Copyright 2002-2023 the original author or authors.
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

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Arrays;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Set;

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
import org.springframework.security.oauth2.core.endpoint.OAuth2DeviceAuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

/**
 * A {@link HttpMessageConverter} for an {@link OAuth2DeviceAuthorizationResponse OAuth
 * 2.0 Device Authorization Response}.
 *
 * @author Steve Riesenberg
 * @since 6.1
 * @see AbstractHttpMessageConverter
 * @see OAuth2DeviceAuthorizationResponse
 */
public class OAuth2DeviceAuthorizationResponseHttpMessageConverter
		extends AbstractHttpMessageConverter<OAuth2DeviceAuthorizationResponse> {

	private static final ParameterizedTypeReference<Map<String, Object>> STRING_OBJECT_MAP = new ParameterizedTypeReference<>() {
	};

	private final GenericHttpMessageConverter<Object> jsonMessageConverter = HttpMessageConverters
		.getJsonMessageConverter();

	private Converter<Map<String, Object>, OAuth2DeviceAuthorizationResponse> deviceAuthorizationResponseConverter = new DefaultMapOAuth2DeviceAuthorizationResponseConverter();

	private Converter<OAuth2DeviceAuthorizationResponse, Map<String, Object>> deviceAuthorizationResponseParametersConverter = new DefaultOAuth2DeviceAuthorizationResponseMapConverter();

	@Override
	protected boolean supports(Class<?> clazz) {
		return OAuth2DeviceAuthorizationResponse.class.isAssignableFrom(clazz);
	}

	@Override
	@SuppressWarnings("unchecked")
	protected OAuth2DeviceAuthorizationResponse readInternal(Class<? extends OAuth2DeviceAuthorizationResponse> clazz,
			HttpInputMessage inputMessage) throws HttpMessageNotReadableException {

		try {
			Map<String, Object> deviceAuthorizationResponseParameters = (Map<String, Object>) this.jsonMessageConverter
				.read(STRING_OBJECT_MAP.getType(), null, inputMessage);
			return this.deviceAuthorizationResponseConverter.convert(deviceAuthorizationResponseParameters);
		}
		catch (Exception ex) {
			throw new HttpMessageNotReadableException(
					"An error occurred reading the OAuth 2.0 Device Authorization Response: " + ex.getMessage(), ex,
					inputMessage);
		}
	}

	@Override
	protected void writeInternal(OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse,
			HttpOutputMessage outputMessage) throws HttpMessageNotWritableException {

		try {
			Map<String, Object> deviceAuthorizationResponseParameters = this.deviceAuthorizationResponseParametersConverter
				.convert(deviceAuthorizationResponse);
			this.jsonMessageConverter.write(deviceAuthorizationResponseParameters, STRING_OBJECT_MAP.getType(),
					MediaType.APPLICATION_JSON, outputMessage);
		}
		catch (Exception ex) {
			throw new HttpMessageNotWritableException(
					"An error occurred writing the OAuth 2.0 Device Authorization Response: " + ex.getMessage(), ex);
		}
	}

	/**
	 * Sets the {@link Converter} used for converting the OAuth 2.0 Device Authorization
	 * Response parameters to an {@link OAuth2DeviceAuthorizationResponse}.
	 * @param deviceAuthorizationResponseConverter the {@link Converter} used for
	 * converting to an {@link OAuth2DeviceAuthorizationResponse}
	 */
	public final void setDeviceAuthorizationResponseConverter(
			Converter<Map<String, Object>, OAuth2DeviceAuthorizationResponse> deviceAuthorizationResponseConverter) {
		Assert.notNull(deviceAuthorizationResponseConverter, "deviceAuthorizationResponseConverter cannot be null");
		this.deviceAuthorizationResponseConverter = deviceAuthorizationResponseConverter;
	}

	/**
	 * Sets the {@link Converter} used for converting the
	 * {@link OAuth2DeviceAuthorizationResponse} to a {@code Map} representation of the
	 * OAuth 2.0 Device Authorization Response parameters.
	 * @param deviceAuthorizationResponseParametersConverter the {@link Converter} used
	 * for converting to a {@code Map} representation of the Device Authorization Response
	 * parameters
	 */
	public final void setDeviceAuthorizationResponseParametersConverter(
			Converter<OAuth2DeviceAuthorizationResponse, Map<String, Object>> deviceAuthorizationResponseParametersConverter) {
		Assert.notNull(deviceAuthorizationResponseParametersConverter,
				"deviceAuthorizationResponseParametersConverter cannot be null");
		this.deviceAuthorizationResponseParametersConverter = deviceAuthorizationResponseParametersConverter;
	}

	private static final class DefaultMapOAuth2DeviceAuthorizationResponseConverter
			implements Converter<Map<String, Object>, OAuth2DeviceAuthorizationResponse> {

		private static final Set<String> DEVICE_AUTHORIZATION_RESPONSE_PARAMETER_NAMES = new HashSet<>(
				Arrays.asList(OAuth2ParameterNames.DEVICE_CODE, OAuth2ParameterNames.USER_CODE,
						OAuth2ParameterNames.VERIFICATION_URI, OAuth2ParameterNames.VERIFICATION_URI_COMPLETE,
						OAuth2ParameterNames.EXPIRES_IN, OAuth2ParameterNames.INTERVAL));

		@Override
		public OAuth2DeviceAuthorizationResponse convert(Map<String, Object> parameters) {
			String deviceCode = getParameterValue(parameters, OAuth2ParameterNames.DEVICE_CODE);
			String userCode = getParameterValue(parameters, OAuth2ParameterNames.USER_CODE);
			String verificationUri = getParameterValue(parameters, OAuth2ParameterNames.VERIFICATION_URI);
			String verificationUriComplete = getParameterValue(parameters,
					OAuth2ParameterNames.VERIFICATION_URI_COMPLETE);
			long expiresIn = getParameterValue(parameters, OAuth2ParameterNames.EXPIRES_IN, 0L);
			long interval = getParameterValue(parameters, OAuth2ParameterNames.INTERVAL, 0L);
			Map<String, Object> additionalParameters = new LinkedHashMap<>();
			parameters.forEach((key, value) -> {
				if (!DEVICE_AUTHORIZATION_RESPONSE_PARAMETER_NAMES.contains(key)) {
					additionalParameters.put(key, value);
				}
			});
			// @formatter:off
			return OAuth2DeviceAuthorizationResponse.with(deviceCode, userCode)
					.verificationUri(verificationUri)
					.verificationUriComplete(verificationUriComplete)
					.expiresIn(expiresIn)
					.interval(interval)
					.additionalParameters(additionalParameters)
					.build();
			// @formatter:on
		}

		private static String getParameterValue(Map<String, Object> parameters, String parameterName) {
			Object obj = parameters.get(parameterName);
			return (obj != null) ? obj.toString() : null;
		}

		private static long getParameterValue(Map<String, Object> parameters, String parameterName, long defaultValue) {
			long parameterValue = defaultValue;

			Object obj = parameters.get(parameterName);
			if (obj != null) {
				// Final classes Long and Integer do not need to be coerced
				if (obj.getClass() == Long.class) {
					parameterValue = (Long) obj;
				}
				else if (obj.getClass() == Integer.class) {
					parameterValue = (Integer) obj;
				}
				else {
					// Attempt to coerce to a long (typically from a String)
					try {
						parameterValue = Long.parseLong(obj.toString());
					}
					catch (NumberFormatException ignored) {
					}
				}
			}

			return parameterValue;
		}

	}

	private static final class DefaultOAuth2DeviceAuthorizationResponseMapConverter
			implements Converter<OAuth2DeviceAuthorizationResponse, Map<String, Object>> {

		@Override
		public Map<String, Object> convert(OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse) {
			Map<String, Object> parameters = new HashMap<>();
			parameters.put(OAuth2ParameterNames.DEVICE_CODE,
					deviceAuthorizationResponse.getDeviceCode().getTokenValue());
			parameters.put(OAuth2ParameterNames.USER_CODE, deviceAuthorizationResponse.getUserCode().getTokenValue());
			parameters.put(OAuth2ParameterNames.VERIFICATION_URI, deviceAuthorizationResponse.getVerificationUri());
			if (StringUtils.hasText(deviceAuthorizationResponse.getVerificationUriComplete())) {
				parameters.put(OAuth2ParameterNames.VERIFICATION_URI_COMPLETE,
						deviceAuthorizationResponse.getVerificationUriComplete());
			}
			parameters.put(OAuth2ParameterNames.EXPIRES_IN, getExpiresIn(deviceAuthorizationResponse));
			if (deviceAuthorizationResponse.getInterval() > 0) {
				parameters.put(OAuth2ParameterNames.INTERVAL, deviceAuthorizationResponse.getInterval());
			}
			if (!CollectionUtils.isEmpty(deviceAuthorizationResponse.getAdditionalParameters())) {
				parameters.putAll(deviceAuthorizationResponse.getAdditionalParameters());
			}
			return parameters;
		}

		private static long getExpiresIn(OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse) {
			if (deviceAuthorizationResponse.getDeviceCode().getExpiresAt() != null) {
				Instant issuedAt = (deviceAuthorizationResponse.getDeviceCode().getIssuedAt() != null)
						? deviceAuthorizationResponse.getDeviceCode().getIssuedAt() : Instant.now();
				return ChronoUnit.SECONDS.between(issuedAt, deviceAuthorizationResponse.getDeviceCode().getExpiresAt());
			}
			return -1;
		}

	}

}
