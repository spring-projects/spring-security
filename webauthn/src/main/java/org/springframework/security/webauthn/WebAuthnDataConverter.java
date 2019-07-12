/*
 * Copyright 2002-2019 the original author or authors.
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

package org.springframework.security.webauthn;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.AttestedCredentialDataConverter;
import com.webauthn4j.converter.AuthenticatorDataConverter;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.JsonConverter;
import org.springframework.util.Assert;

public class WebAuthnDataConverter {

	private ObjectMapper jsonMapper;
	private ObjectMapper cborMapper;

	private AttestationObjectConverter attestationObjectConverter;
	private AuthenticatorDataConverter authenticatorDataConverter;
	private AttestedCredentialDataConverter attestedCredentialDataConverter;

	public WebAuthnDataConverter(ObjectMapper jsonMapper, ObjectMapper cborMapper) {
		Assert.notNull(jsonMapper, "jsonMapper must not be null");
		Assert.notNull(cborMapper, "cborMapper must not be null");

		this.jsonMapper = jsonMapper;
		this.cborMapper = cborMapper;
		JsonConverter jsonConverter = new JsonConverter(jsonMapper, cborMapper);
		CborConverter cborConverter = jsonConverter.getCborConverter();

		this.attestationObjectConverter = new AttestationObjectConverter(cborConverter);
		this.authenticatorDataConverter = new AuthenticatorDataConverter(cborConverter);
		this.attestedCredentialDataConverter = new AttestedCredentialDataConverter(cborConverter);
	}

	public WebAuthnDataConverter() {
		this(new ObjectMapper(), new ObjectMapper(new CBORFactory()));
	}


	public byte[] extractAuthenticatorData(byte[] attestationObject) {
		return attestationObjectConverter.extractAuthenticatorData(attestationObject);
	}

	public byte[] extractAttestedCredentialData(byte[] authenticatorData) {
		return authenticatorDataConverter.extractAttestedCredentialData(authenticatorData);
	}

	public byte[] extractCredentialId(byte[] attestedCredentialData) {
		return attestedCredentialDataConverter.extractCredentialId(attestedCredentialData);
	}

	public long extractSignCount(byte[] authenticatorData) {
		return authenticatorDataConverter.extractSignCount(authenticatorData);
	}

	public ObjectMapper getJsonMapper() {
		return jsonMapper;
	}

	public ObjectMapper getCborMapper() {
		return cborMapper;
	}
}
