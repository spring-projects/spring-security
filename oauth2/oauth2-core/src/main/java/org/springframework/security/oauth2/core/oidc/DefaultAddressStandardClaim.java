/*
 * Copyright 2002-2017 the original author or authors.
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

package org.springframework.security.oauth2.core.oidc;

import java.util.Map;

/**
 * The default implementation of an {@link AddressStandardClaim Address Claim}.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see AddressStandardClaim
 */
public final class DefaultAddressStandardClaim implements AddressStandardClaim {

	private String formatted;

	private String streetAddress;

	private String locality;

	private String region;

	private String postalCode;

	private String country;

	private DefaultAddressStandardClaim() {
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

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}
		if (obj == null || !AddressStandardClaim.class.isAssignableFrom(obj.getClass())) {
			return false;
		}

		AddressStandardClaim that = (AddressStandardClaim) obj;

		if (this.getFormatted() != null ? !this.getFormatted().equals(that.getFormatted())
				: that.getFormatted() != null) {
			return false;
		}
		if (this.getStreetAddress() != null ? !this.getStreetAddress().equals(that.getStreetAddress())
				: that.getStreetAddress() != null) {
			return false;
		}
		if (this.getLocality() != null ? !this.getLocality().equals(that.getLocality()) : that.getLocality() != null) {
			return false;
		}
		if (this.getRegion() != null ? !this.getRegion().equals(that.getRegion()) : that.getRegion() != null) {
			return false;
		}
		if (this.getPostalCode() != null ? !this.getPostalCode().equals(that.getPostalCode())
				: that.getPostalCode() != null) {
			return false;
		}
		return this.getCountry() != null ? this.getCountry().equals(that.getCountry()) : that.getCountry() == null;
	}

	@Override
	public int hashCode() {
		int result = this.getFormatted() != null ? this.getFormatted().hashCode() : 0;
		result = 31 * result + (this.getStreetAddress() != null ? this.getStreetAddress().hashCode() : 0);
		result = 31 * result + (this.getLocality() != null ? this.getLocality().hashCode() : 0);
		result = 31 * result + (this.getRegion() != null ? this.getRegion().hashCode() : 0);
		result = 31 * result + (this.getPostalCode() != null ? this.getPostalCode().hashCode() : 0);
		result = 31 * result + (this.getCountry() != null ? this.getCountry().hashCode() : 0);
		return result;
	}

	/**
	 * A builder for {@link DefaultAddressStandardClaim}.
	 */
	public static class Builder {

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

		/**
		 * Default constructor.
		 */
		public Builder() {
		}

		/**
		 * Constructs and initializes the address attributes using the provided
		 * {@code addressFields}.
		 * @param addressFields the fields used to initialize the address attributes
		 */
		public Builder(Map<String, Object> addressFields) {
			this.formatted((String) addressFields.get(FORMATTED_FIELD_NAME));
			this.streetAddress((String) addressFields.get(STREET_ADDRESS_FIELD_NAME));
			this.locality((String) addressFields.get(LOCALITY_FIELD_NAME));
			this.region((String) addressFields.get(REGION_FIELD_NAME));
			this.postalCode((String) addressFields.get(POSTAL_CODE_FIELD_NAME));
			this.country((String) addressFields.get(COUNTRY_FIELD_NAME));
		}

		/**
		 * Sets the full mailing address, formatted for display.
		 * @param formatted the full mailing address
		 * @return the {@link Builder}
		 */
		public Builder formatted(String formatted) {
			this.formatted = formatted;
			return this;
		}

		/**
		 * Sets the full street address, which may include house number, street name, P.O.
		 * Box, etc.
		 * @param streetAddress the full street address
		 * @return the {@link Builder}
		 */
		public Builder streetAddress(String streetAddress) {
			this.streetAddress = streetAddress;
			return this;
		}

		/**
		 * Sets the city or locality.
		 * @param locality the city or locality
		 * @return the {@link Builder}
		 */
		public Builder locality(String locality) {
			this.locality = locality;
			return this;
		}

		/**
		 * Sets the state, province, prefecture, or region.
		 * @param region the state, province, prefecture, or region
		 * @return the {@link Builder}
		 */
		public Builder region(String region) {
			this.region = region;
			return this;
		}

		/**
		 * Sets the zip code or postal code.
		 * @param postalCode the zip code or postal code
		 * @return the {@link Builder}
		 */
		public Builder postalCode(String postalCode) {
			this.postalCode = postalCode;
			return this;
		}

		/**
		 * Sets the country.
		 * @param country the country
		 * @return the {@link Builder}
		 */
		public Builder country(String country) {
			this.country = country;
			return this;
		}

		/**
		 * Builds a new {@link DefaultAddressStandardClaim}.
		 * @return a {@link AddressStandardClaim}
		 */
		public AddressStandardClaim build() {
			DefaultAddressStandardClaim address = new DefaultAddressStandardClaim();
			address.formatted = this.formatted;
			address.streetAddress = this.streetAddress;
			address.locality = this.locality;
			address.region = this.region;
			address.postalCode = this.postalCode;
			address.country = this.country;

			return address;
		}

	}

}
