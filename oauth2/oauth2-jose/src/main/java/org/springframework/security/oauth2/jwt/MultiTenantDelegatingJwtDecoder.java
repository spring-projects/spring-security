/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.jwt;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jose.util.JSONObjectUtils;
import net.minidev.json.JSONObject;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.text.ParseException;
import java.util.Map;

/**
 * Delegating JWT decoder that parses JWT and based off {code iss} claim delegates
 * further processing to respective underlying decoder.
 *
 * @author Gladwin Burboz
 * @since 5.2
 */
public class MultiTenantDelegatingJwtDecoder implements JwtDecoder {
	private static final String DECODING_ERROR_MESSAGE_TEMPLATE =
			"An error occurred while attempting to decode the Jwt: %s";

	private JwtDecoder decoderDefault;

	private Map<String, JwtDecoder> decoderByIssuer;

	/**
	 * Constructs a {@code MultiTenantDelegatingJwtDecoder} using the provided parameters.
	 *
	 * @param decoderDefault the default decoder to use for JWT
	 */
	public MultiTenantDelegatingJwtDecoder(JwtDecoder decoderDefault) {
		this(decoderDefault, null);
	}

	/**
	 * Constructs a {@code MultiTenantDelegatingJwtDecoder} using the provided parameters.
	 *
	 * @param decoderByIssuer the decoder to use for JWT based off issuer as a key
	 */
	public MultiTenantDelegatingJwtDecoder(
			Map<String, JwtDecoder> decoderByIssuer) {
		this(null, decoderByIssuer);
	}

	/**
	 * Constructs a {@code MultiTenantDelegatingJwtDecoder} using the provided parameters.
	 *
	 * @param decoderDefault the default decoder to use for JWT
	 * @param decoderByIssuer the decoder to use for JWT based off issuer as a key
	 */
	public MultiTenantDelegatingJwtDecoder(
			JwtDecoder decoderDefault,
			Map<String, JwtDecoder> decoderByIssuer) {
		Assert.isTrue(decoderDefault != null || !CollectionUtils.isEmpty(decoderByIssuer),
				"At least one of decoderDefault or decoderByIssuer must be provided");
		this.decoderDefault = decoderDefault;
		this.decoderByIssuer = decoderByIssuer;
	}

	@Override
	public Jwt decode(String token) throws JwtException {
		JwtDecoder jwtDecoder = null;
		if (!CollectionUtils.isEmpty(decoderByIssuer)) {
			String issuer = parseAndFindIssuer(token);
			if (issuer == null && decoderDefault == null) {
				throw new JwtException(
						"Unable to determine issuer for the token");
			} else {
				jwtDecoder = decoderByIssuer.get(issuer);
				if (jwtDecoder == null && decoderDefault == null) {
					throw new JwtException(String.format(
							"JwtDecoder has not been configured for issuer %s", issuer));
				}
			}
		}
		if (jwtDecoder == null && decoderDefault != null) {
			jwtDecoder = decoderDefault;
		} else {
			throw new JwtException(String.format("Unable to determine JwtDecoder"));
		}
		return jwtDecoder.decode(token);
	}

	private String parseAndFindIssuer(String token) {
		try {
			Base64URL[] parts = JOSEObject.split(token);
			JSONObject payload = JSONObjectUtils.parse(parts[1].decodeToString());
			return payload.getAsString("iss");
		} catch (ArrayIndexOutOfBoundsException
				| NullPointerException
				| ParseException ex) {
			throw new JwtException(String.format(
					DECODING_ERROR_MESSAGE_TEMPLATE, ex.getMessage()), ex);
		}
	}

}
