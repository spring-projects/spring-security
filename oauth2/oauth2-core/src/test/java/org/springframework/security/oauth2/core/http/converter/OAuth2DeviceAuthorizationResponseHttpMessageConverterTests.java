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
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpStatus;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.mock.http.MockHttpOutputMessage;
import org.springframework.mock.http.client.MockClientHttpResponse;
import org.springframework.security.oauth2.core.endpoint.OAuth2DeviceAuthorizationResponse;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.entry;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link OAuth2DeviceAuthorizationResponseHttpMessageConverter}.
 *
 * @author Steve Riesenberg
 */
public class OAuth2DeviceAuthorizationResponseHttpMessageConverterTests {

	private OAuth2DeviceAuthorizationResponseHttpMessageConverter messageConverter;

	@BeforeEach
	public void setup() {
		this.messageConverter = new OAuth2DeviceAuthorizationResponseHttpMessageConverter();
	}

	@Test
	public void supportsWhenOAuth2DeviceAuthorizationResponseThenTrue() {
		assertThat(this.messageConverter.supports(OAuth2DeviceAuthorizationResponse.class)).isTrue();
	}

	@Test
	public void setDeviceAuthorizationResponseConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setDeviceAuthorizationResponseConverter(null));
	}

	@Test
	public void setDeviceAuthorizationResponseParametersConverterWhenConverterIsNullThenThrowIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.messageConverter.setDeviceAuthorizationResponseParametersConverter(null));
	}

	@Test
	public void readInternalWhenSuccessfulResponseWithAllParametersThenReadOAuth2DeviceAuthorizationResponse() {
		// @formatter:off
		String authorizationResponse = """
				{
					"device_code": "GmRhm_DnyEy",
					"user_code": "WDJB-MJHT",
					"verification_uri": "https://example.com/device",
					"verification_uri_complete": "https://example.com/device?user_code=WDJB-MJHT",
					"expires_in": 1800,
					"interval": 5,
					"custom_parameter_1": "custom-value-1",
					"custom_parameter_2": "custom-value-2"
				}
				""";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(authorizationResponse.getBytes(), HttpStatus.OK);
		OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse = this.messageConverter
			.readInternal(OAuth2DeviceAuthorizationResponse.class, response);
		assertThat(deviceAuthorizationResponse.getDeviceCode().getTokenValue()).isEqualTo("GmRhm_DnyEy");
		assertThat(deviceAuthorizationResponse.getDeviceCode().getIssuedAt()).isNotNull();
		assertThat(deviceAuthorizationResponse.getDeviceCode().getExpiresAt())
			.isBeforeOrEqualTo(Instant.now().plusSeconds(1800));
		assertThat(deviceAuthorizationResponse.getUserCode().getTokenValue()).isEqualTo("WDJB-MJHT");
		assertThat(deviceAuthorizationResponse.getUserCode().getIssuedAt())
			.isEqualTo(deviceAuthorizationResponse.getDeviceCode().getIssuedAt());
		assertThat(deviceAuthorizationResponse.getUserCode().getExpiresAt())
			.isEqualTo(deviceAuthorizationResponse.getDeviceCode().getExpiresAt());
		assertThat(deviceAuthorizationResponse.getVerificationUri()).isEqualTo("https://example.com/device");
		assertThat(deviceAuthorizationResponse.getVerificationUriComplete())
			.isEqualTo("https://example.com/device?user_code=WDJB-MJHT");
		assertThat(deviceAuthorizationResponse.getInterval()).isEqualTo(5);
		assertThat(deviceAuthorizationResponse.getAdditionalParameters()).containsExactly(
				entry("custom_parameter_1", "custom-value-1"), entry("custom_parameter_2", "custom-value-2"));
	}

	@Test
	public void readInternalWhenSuccessfulResponseWithNullValuesThenReadOAuth2DeviceAuthorizationResponse() {
		// @formatter:off
		String authorizationResponse = """
				{
					"device_code": "GmRhm_DnyEy",
					"user_code": "WDJB-MJHT",
					"verification_uri": "https://example.com/device",
					"verification_uri_complete": null,
					"expires_in": 1800,
					"interval": null
				}
				""";
		// @formatter:on
		MockClientHttpResponse response = new MockClientHttpResponse(authorizationResponse.getBytes(), HttpStatus.OK);
		OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse = this.messageConverter
			.readInternal(OAuth2DeviceAuthorizationResponse.class, response);
		assertThat(deviceAuthorizationResponse.getDeviceCode().getTokenValue()).isEqualTo("GmRhm_DnyEy");
		assertThat(deviceAuthorizationResponse.getDeviceCode().getIssuedAt()).isNotNull();
		assertThat(deviceAuthorizationResponse.getDeviceCode().getExpiresAt())
			.isBeforeOrEqualTo(Instant.now().plusSeconds(1800));
		assertThat(deviceAuthorizationResponse.getUserCode().getTokenValue()).isEqualTo("WDJB-MJHT");
		assertThat(deviceAuthorizationResponse.getUserCode().getIssuedAt())
			.isEqualTo(deviceAuthorizationResponse.getDeviceCode().getIssuedAt());
		assertThat(deviceAuthorizationResponse.getUserCode().getExpiresAt())
			.isEqualTo(deviceAuthorizationResponse.getDeviceCode().getExpiresAt());
		assertThat(deviceAuthorizationResponse.getVerificationUri()).isEqualTo("https://example.com/device");
		assertThat(deviceAuthorizationResponse.getVerificationUriComplete()).isNull();
		assertThat(deviceAuthorizationResponse.getInterval()).isEqualTo(0);
	}

	@Test
	@SuppressWarnings("unchecked")
	public void readInternalWhenConversionFailsThenThrowHttpMessageNotReadableException() {
		Converter<Map<String, Object>, OAuth2DeviceAuthorizationResponse> deviceAuthorizationResponseConverter = mock(
				Converter.class);
		given(deviceAuthorizationResponseConverter.convert(any())).willThrow(RuntimeException.class);
		this.messageConverter.setDeviceAuthorizationResponseConverter(deviceAuthorizationResponseConverter);
		String authorizationResponse = "{}";
		MockClientHttpResponse response = new MockClientHttpResponse(authorizationResponse.getBytes(), HttpStatus.OK);
		assertThatExceptionOfType(HttpMessageNotReadableException.class)
			.isThrownBy(() -> this.messageConverter.readInternal(OAuth2DeviceAuthorizationResponse.class, response))
			.withMessageContaining("An error occurred reading the OAuth 2.0 Device Authorization Response");
	}

	@Test
	public void writeInternalWhenOAuth2DeviceAuthorizationResponseThenWriteResponse() {
		Map<String, Object> additionalParameters = new HashMap<>();
		additionalParameters.put("custom_parameter_1", "custom-value-1");
		additionalParameters.put("custom_parameter_2", "custom-value-2");
		// @formatter:off
		OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse =
				OAuth2DeviceAuthorizationResponse.with("GmRhm_DnyEy", "WDJB-MJHT")
						.verificationUri("https://example.com/device")
						.verificationUriComplete("https://example.com/device?user_code=WDJB-MJHT")
						.expiresIn(1800)
						.interval(5)
						.additionalParameters(additionalParameters)
						.build();
		// @formatter:on
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();
		this.messageConverter.writeInternal(deviceAuthorizationResponse, outputMessage);
		String authorizationResponse = outputMessage.getBodyAsString();
		assertThat(authorizationResponse).contains("\"device_code\":\"GmRhm_DnyEy\"");
		assertThat(authorizationResponse).contains("\"user_code\":\"WDJB-MJHT\"");
		assertThat(authorizationResponse).contains("\"verification_uri\":\"https://example.com/device\"");
		assertThat(authorizationResponse)
			.contains("\"verification_uri_complete\":\"https://example.com/device?user_code=WDJB-MJHT\"");
		assertThat(authorizationResponse).contains("\"expires_in\":1800");
		assertThat(authorizationResponse).contains("\"interval\":5");
		assertThat(authorizationResponse).contains("\"custom_parameter_1\":\"custom-value-1\"");
		assertThat(authorizationResponse).contains("\"custom_parameter_2\":\"custom-value-2\"");
	}

	@Test
	@SuppressWarnings("unchecked")
	public void writeInternalWhenConversionFailsThenThrowHttpMessageNotWritableException() {
		Converter<OAuth2DeviceAuthorizationResponse, Map<String, Object>> deviceAuthorizationResponseParametersConverter = mock(
				Converter.class);
		given(deviceAuthorizationResponseParametersConverter.convert(any())).willThrow(RuntimeException.class);
		this.messageConverter
			.setDeviceAuthorizationResponseParametersConverter(deviceAuthorizationResponseParametersConverter);
		// @formatter:off
		OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse =
				OAuth2DeviceAuthorizationResponse.with("GmRhm_DnyEy", "WDJB-MJHT")
						.verificationUri("https://example.com/device")
						.expiresIn(1800)
						.build();
		// @formatter:on
		MockHttpOutputMessage outputMessage = new MockHttpOutputMessage();
		assertThatExceptionOfType(HttpMessageNotWritableException.class)
			.isThrownBy(() -> this.messageConverter.writeInternal(deviceAuthorizationResponse, outputMessage))
			.withMessageContaining("An error occurred writing the OAuth 2.0 Device Authorization Response");
	}

}
