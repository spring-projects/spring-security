/*
 * Copyright 2002-2024 the original author or authors.
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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import javax.xml.namespace.QName;

import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.w3c.dom.Element;

import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.web.util.UriComponentsBuilder;

interface OpenSamlOperations {

	<T extends XMLObject> T build(QName elementName);

	<T extends XMLObject> T deserialize(String serialized);

	<T extends XMLObject> T deserialize(InputStream serialized);

	SerializationConfigurer<?> serialize(XMLObject object);

	SerializationConfigurer<?> serialize(Element element);

	SignatureConfigurer<?> withSigningKeys(Collection<Saml2X509Credential> credentials);

	VerificationConfigurer withVerificationKeys(Collection<Saml2X509Credential> credentials);

	DecryptionConfigurer withDecryptionKeys(Collection<Saml2X509Credential> credentials);

	interface SerializationConfigurer<B extends SerializationConfigurer<B>> {

		B prettyPrint(boolean pretty);

		String serialize();

	}

	interface SignatureConfigurer<B extends SignatureConfigurer<B>> {

		B algorithms(List<String> algs);

		<O extends SignableXMLObject> O sign(O object);

		Map<String, String> sign(Map<String, String> params);

	}

	interface VerificationConfigurer {

		VerificationConfigurer entityId(String entityId);

		Collection<Saml2Error> verify(SignableXMLObject signable);

		Collection<Saml2Error> verify(VerificationConfigurer.RedirectParameters parameters);

		final class RedirectParameters {

			private final String id;

			private final Issuer issuer;

			private final String algorithm;

			private final byte[] signature;

			private final byte[] content;

			RedirectParameters(Map<String, String> parameters, String parametersQuery, RequestAbstractType request) {
				this.id = request.getID();
				this.issuer = request.getIssuer();
				this.algorithm = parameters.get(Saml2ParameterNames.SIG_ALG);
				if (parameters.get(Saml2ParameterNames.SIGNATURE) != null) {
					this.signature = Saml2Utils.samlDecode(parameters.get(Saml2ParameterNames.SIGNATURE));
				}
				else {
					this.signature = null;
				}
				Map<String, String> queryParams = UriComponentsBuilder.newInstance()
					.query(parametersQuery)
					.build(true)
					.getQueryParams()
					.toSingleValueMap();
				String relayState = parameters.get(Saml2ParameterNames.RELAY_STATE);
				this.content = getContent(Saml2ParameterNames.SAML_REQUEST, relayState, queryParams);
			}

			RedirectParameters(Map<String, String> parameters, String parametersQuery, StatusResponseType response) {
				this.id = response.getID();
				this.issuer = response.getIssuer();
				this.algorithm = parameters.get(Saml2ParameterNames.SIG_ALG);
				if (parameters.get(Saml2ParameterNames.SIGNATURE) != null) {
					this.signature = Saml2Utils.samlDecode(parameters.get(Saml2ParameterNames.SIGNATURE));
				}
				else {
					this.signature = null;
				}
				Map<String, String> queryParams = UriComponentsBuilder.newInstance()
					.query(parametersQuery)
					.build(true)
					.getQueryParams()
					.toSingleValueMap();
				String relayState = parameters.get(Saml2ParameterNames.RELAY_STATE);
				this.content = getContent(Saml2ParameterNames.SAML_RESPONSE, relayState, queryParams);
			}

			static byte[] getContent(String samlObject, String relayState, final Map<String, String> queryParams) {
				if (Objects.nonNull(relayState)) {
					return String
						.format("%s=%s&%s=%s&%s=%s", samlObject, queryParams.get(samlObject),
								Saml2ParameterNames.RELAY_STATE, queryParams.get(Saml2ParameterNames.RELAY_STATE),
								Saml2ParameterNames.SIG_ALG, queryParams.get(Saml2ParameterNames.SIG_ALG))
						.getBytes(StandardCharsets.UTF_8);
				}
				else {
					return String
						.format("%s=%s&%s=%s", samlObject, queryParams.get(samlObject), Saml2ParameterNames.SIG_ALG,
								queryParams.get(Saml2ParameterNames.SIG_ALG))
						.getBytes(StandardCharsets.UTF_8);
				}
			}

			String getId() {
				return this.id;
			}

			Issuer getIssuer() {
				return this.issuer;
			}

			byte[] getContent() {
				return this.content;
			}

			String getAlgorithm() {
				return this.algorithm;
			}

			byte[] getSignature() {
				return this.signature;
			}

			boolean hasSignature() {
				return this.signature != null;
			}

		}

	}

	interface DecryptionConfigurer {

		void decrypt(XMLObject object);

	}

}
