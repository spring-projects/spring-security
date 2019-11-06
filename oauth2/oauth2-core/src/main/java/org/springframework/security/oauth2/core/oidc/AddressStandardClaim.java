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

/**
 * The Address Claim represents a physical mailing address defined by the OpenID Connect Core 1.0 specification
 * that can be returned either in the UserInfo Response or the ID Token.
 *
 * @author Joe Grandja
 * @since 5.0
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#AddressClaim">Address Claim</a>
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#UserInfoResponse">UserInfo Response</a>
 * @see <a target="_blank" href="https://openid.net/specs/openid-connect-core-1_0.html#IDToken">ID Token</a>
 */
public interface AddressStandardClaim {

	/**
	 * Returns the full mailing address, formatted for display.
	 *
	 * @return the full mailing address
	 */
	String getFormatted();

	/**
	 * Returns the full street address, which may include house number, street name, P.O. Box, etc.
	 *
	 * @return the full street address
	 */
	String getStreetAddress();

	/**
	 * Returns the city or locality.
	 *
	 * @return the city or locality
	 */
	String getLocality();

	/**
	 * Returns the state, province, prefecture, or region.
	 *
	 * @return the state, province, prefecture, or region
	 */
	String getRegion();

	/**
	 * Returns the zip code or postal code.
	 *
	 * @return the zip code or postal code
	 */
	String getPostalCode();

	/**
	 * Returns the country.
	 *
	 * @return the country
	 */
	String getCountry();

}
