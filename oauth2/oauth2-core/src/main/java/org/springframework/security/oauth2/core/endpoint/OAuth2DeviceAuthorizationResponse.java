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

package org.springframework.security.oauth2.core.endpoint;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Map;

import org.springframework.security.oauth2.core.OAuth2DeviceCode;
import org.springframework.security.oauth2.core.OAuth2UserCode;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

/**
 * A representation of an OAuth 2.0 Device Authorization Response.
 *
 * @author Steve Riesenberg
 * @since 6.1
 * @see OAuth2DeviceCode
 * @see OAuth2UserCode
 * @see <a target="_blank" href="https://tools.ietf.org/html/rfc8628#section-3.2">Section
 * 3.2 Device Authorization Response</a>
 */
public final class OAuth2DeviceAuthorizationResponse {

	private OAuth2DeviceCode deviceCode;

	private OAuth2UserCode userCode;

	private String verificationUri;

	private String verificationUriComplete;

	private long interval;

	private Map<String, Object> additionalParameters;

	private OAuth2DeviceAuthorizationResponse() {
	}

	/**
	 * Returns the {@link OAuth2DeviceCode Device Code}.
	 * @return the {@link OAuth2DeviceCode}
	 */
	public OAuth2DeviceCode getDeviceCode() {
		return this.deviceCode;
	}

	/**
	 * Returns the {@link OAuth2UserCode User Code}.
	 * @return the {@link OAuth2UserCode}
	 */
	public OAuth2UserCode getUserCode() {
		return this.userCode;
	}

	/**
	 * Returns the end-user verification URI.
	 * @return the end-user verification URI
	 */
	public String getVerificationUri() {
		return this.verificationUri;
	}

	/**
	 * Returns the end-user verification URI that includes the user code.
	 * @return the end-user verification URI that includes the user code
	 */
	public String getVerificationUriComplete() {
		return this.verificationUriComplete;
	}

	/**
	 * Returns the minimum amount of time (in seconds) that the client should wait between
	 * polling requests to the token endpoint.
	 * @return the minimum amount of time between polling requests
	 */
	public long getInterval() {
		return this.interval;
	}

	/**
	 * Returns the additional parameters returned in the response.
	 * @return a {@code Map} of the additional parameters returned in the response, may be
	 * empty.
	 */
	public Map<String, Object> getAdditionalParameters() {
		return this.additionalParameters;
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided device code and user
	 * code values.
	 * @param deviceCode the value of the device code
	 * @param userCode the value of the user code
	 * @return the {@link Builder}
	 */
	public static Builder with(String deviceCode, String userCode) {
		Assert.hasText(deviceCode, "deviceCode cannot be empty");
		Assert.hasText(userCode, "userCode cannot be empty");
		return new Builder(deviceCode, userCode);
	}

	/**
	 * Returns a new {@link Builder}, initialized with the provided device code and user
	 * code.
	 * @param deviceCode the {@link OAuth2DeviceCode}
	 * @param userCode the {@link OAuth2UserCode}
	 * @return the {@link Builder}
	 */
	public static Builder with(OAuth2DeviceCode deviceCode, OAuth2UserCode userCode) {
		Assert.notNull(deviceCode, "deviceCode cannot be null");
		Assert.notNull(userCode, "userCode cannot be null");
		return new Builder(deviceCode, userCode);
	}

	/**
	 * A builder for {@link OAuth2DeviceAuthorizationResponse}.
	 */
	public static final class Builder {

		private final String deviceCode;

		private final String userCode;

		private String verificationUri;

		private String verificationUriComplete;

		private long expiresIn;

		private long interval;

		private Map<String, Object> additionalParameters;

		private Builder(OAuth2DeviceCode deviceCode, OAuth2UserCode userCode) {
			this.deviceCode = deviceCode.getTokenValue();
			this.userCode = userCode.getTokenValue();
			this.expiresIn = ChronoUnit.SECONDS.between(deviceCode.getIssuedAt(), deviceCode.getExpiresAt());
		}

		private Builder(String deviceCode, String userCode) {
			this.deviceCode = deviceCode;
			this.userCode = userCode;
		}

		/**
		 * Sets the end-user verification URI.
		 * @param verificationUri the end-user verification URI
		 * @return the {@link Builder}
		 */
		public Builder verificationUri(String verificationUri) {
			this.verificationUri = verificationUri;
			return this;
		}

		/**
		 * Sets the end-user verification URI that includes the user code.
		 * @param verificationUriComplete the end-user verification URI that includes the
		 * user code
		 * @return the {@link Builder}
		 */
		public Builder verificationUriComplete(String verificationUriComplete) {
			this.verificationUriComplete = verificationUriComplete;
			return this;
		}

		/**
		 * Sets the lifetime (in seconds) of the device code and user code.
		 * @param expiresIn the lifetime (in seconds) of the device code and user code
		 * @return the {@link Builder}
		 */
		public Builder expiresIn(long expiresIn) {
			this.expiresIn = expiresIn;
			return this;
		}

		/**
		 * Sets the minimum amount of time (in seconds) that the client should wait
		 * between polling requests to the token endpoint.
		 * @param interval the minimum amount of time between polling requests
		 * @return the {@link Builder}
		 */
		public Builder interval(long interval) {
			this.interval = interval;
			return this;
		}

		/**
		 * Sets the additional parameters returned in the response.
		 * @param additionalParameters the additional parameters returned in the response
		 * @return the {@link Builder}
		 */
		public Builder additionalParameters(Map<String, Object> additionalParameters) {
			this.additionalParameters = additionalParameters;
			return this;
		}

		/**
		 * Builds a new {@link OAuth2DeviceAuthorizationResponse}.
		 * @return a {@link OAuth2DeviceAuthorizationResponse}
		 */
		public OAuth2DeviceAuthorizationResponse build() {
			Assert.hasText(this.verificationUri, "verificationUri cannot be empty");
			Assert.isTrue(this.expiresIn > 0, "expiresIn must be greater than zero");

			Instant issuedAt = Instant.now();
			Instant expiresAt = issuedAt.plusSeconds(this.expiresIn);
			OAuth2DeviceCode deviceCode = new OAuth2DeviceCode(this.deviceCode, issuedAt, expiresAt);
			OAuth2UserCode userCode = new OAuth2UserCode(this.userCode, issuedAt, expiresAt);

			OAuth2DeviceAuthorizationResponse deviceAuthorizationResponse = new OAuth2DeviceAuthorizationResponse();
			deviceAuthorizationResponse.deviceCode = deviceCode;
			deviceAuthorizationResponse.userCode = userCode;
			deviceAuthorizationResponse.verificationUri = this.verificationUri;
			deviceAuthorizationResponse.verificationUriComplete = this.verificationUriComplete;
			deviceAuthorizationResponse.interval = this.interval;
			deviceAuthorizationResponse.additionalParameters = Collections
				.unmodifiableMap(CollectionUtils.isEmpty(this.additionalParameters) ? Collections.emptyMap()
						: this.additionalParameters);

			return deviceAuthorizationResponse;
		}

	}

}
