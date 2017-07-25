/*
 * Copyright 2012-2017 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.oauth2.oidc.core;

import java.util.Map;

/**
 * The Address Claim represents a physical mailing address defined by the <i>OpenID Connect Core 1.0</i> specification
 * that can be returned either in the <i>UserInfo Response</i> or the <i>ID Token</i>.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#AddressClaim">Address Claim</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">UserInfo Response</a>
 * @see <a target="_blank" href="http://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 */
public interface Address {

	String getFormatted();

	String getStreetAddress();

	String getLocality();

	String getRegion();

	String getPostalCode();

	String getCountry();

	class Builder implements Address {
		private static final String FORMATTED_FIELD_NAME = "formatted";
		private static final String STREET_ADDRESS_FIELD_NAME = "street_address";
		private static final String LOCALITY_FIELD_NAME = "locality";
		private static final String REGION_FIELD_NAME = "region";
		private static final String POSTAL_CODE_FIELD_NAME = "postal_code";
		private static final String COUNTRY_FIELD_NAME = "country";
		private String formatted;
		private String streetAddress;
		private String locality;
		private String region;
		private String postalCode;
		private String country;

		public Builder() {
		}

		public Builder(Map<String, Object> addressFields) {
			this.formatted((String)addressFields.get(FORMATTED_FIELD_NAME));
			this.streetAddress((String)addressFields.get(STREET_ADDRESS_FIELD_NAME));
			this.locality((String)addressFields.get(LOCALITY_FIELD_NAME));
			this.region((String)addressFields.get(REGION_FIELD_NAME));
			this.postalCode((String)addressFields.get(POSTAL_CODE_FIELD_NAME));
			this.country((String)addressFields.get(COUNTRY_FIELD_NAME));
		}

		public Builder formatted(String formatted) {
			this.formatted = formatted;
			return this;
		}

		public Builder streetAddress(String streetAddress) {
			this.streetAddress = streetAddress;
			return this;
		}

		public Builder locality(String locality) {
			this.locality = locality;
			return this;
		}

		public Builder region(String region) {
			this.region = region;
			return this;
		}

		public Builder postalCode(String postalCode) {
			this.postalCode = postalCode;
			return this;
		}

		public Builder country(String country) {
			this.country = country;
			return this;
		}

		public Address build() {
			return this;
		}

		@Override
		public String getFormatted() {
			return this.formatted;
		}

		@Override
		public String getStreetAddress() {
			return this.streetAddress;
		}

		@Override
		public String getLocality() {
			return this.locality;
		}

		@Override
		public String getRegion() {
			return this.region;
		}

		@Override
		public String getPostalCode() {
			return this.postalCode;
		}

		@Override
		public String getCountry() {
			return this.country;
		}
	}
}
