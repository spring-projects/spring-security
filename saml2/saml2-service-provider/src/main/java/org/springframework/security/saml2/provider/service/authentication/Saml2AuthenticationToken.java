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

package org.springframework.security.saml2.provider.service.authentication;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.saml2.credentials.Saml2X509Credential;

import java.util.List;

/**
 * Represents an incoming SAML 2.0 response containing an assertion that has not been validated.
 * {@link Saml2AuthenticationToken#isAuthenticated()} will always return false.
 * @since 5.2
 */
public class Saml2AuthenticationToken extends AbstractAuthenticationToken {

	private final String saml2Response;
	private final String recipientUri;
	private String idpEntityId;
	private String localSpEntityId;
	private List<Saml2X509Credential> credentials;

	/**
	 * Creates an authentication token from an incoming SAML 2 Response object
	 * @param saml2Response inflated and decoded XML representation of the SAML 2 Response
	 * @param recipientUri the URL that the SAML 2 Response was received at. Used for validation
	 * @param idpEntityId the entity ID of the asserting entity
	 * @param localSpEntityId the configured local SP, the relying party, entity ID
	 * @param credentials the credentials configured for signature verification and decryption
	 */
	public Saml2AuthenticationToken(String saml2Response,
									String recipientUri,
									String idpEntityId,
									String localSpEntityId,
									List<Saml2X509Credential> credentials) {
		super(null);
		this.saml2Response = saml2Response;
		this.recipientUri = recipientUri;
		this.idpEntityId = idpEntityId;
		this.localSpEntityId = localSpEntityId;
		this.credentials = credentials;
	}

	/**
	 * Returns the decoded and inflated SAML 2.0 Response XML object as a string
	 * @return decoded and inflated XML data as a {@link String}
	 */
	@Override
	public Object getCredentials() {
		return getSaml2Response();
	}

	/**
	 * Always returns null.
	 * @return null
	 */
	@Override
	public Object getPrincipal() {
		return null;
	}

	/**
	 * Returns inflated and decoded XML representation of the SAML 2 Response
	 * @return inflated and decoded XML representation of the SAML 2 Response
	 */
	public String getSaml2Response() {
		return this.saml2Response;
	}

	/**
	 * Returns the URI that the SAML 2 Response object came in on
	 * @return URI as a string
	 */
	public String getRecipientUri() {
		return this.recipientUri;
	}

	/**
	 * Returns the configured entity ID of the receiving relying party, SP
	 * @return an entityID for the configured local relying party
	 */
	public String getLocalSpEntityId() {
		return this.localSpEntityId;
	}

	/**
	 * Returns all the credentials associated with the relying party configuraiton
	 * @return
	 */
	public List<Saml2X509Credential> getX509Credentials() {
		return this.credentials;
	}

	/**
	 * @return false
	 */
	@Override
	public boolean isAuthenticated() {
		return false;
	}

	/**
	 * The state of this object cannot be changed. Will always throw an exception
	 * @param authenticated ignored
	 * @throws {@link IllegalArgumentException}
	 */
	@Override
	public void setAuthenticated(boolean authenticated) {
		throw new IllegalArgumentException();
	}

	/**
	 * Returns the configured IDP, asserting party, entity ID
	 * @return a string representing the entity ID
	 */
	public String getIdpEntityId() {
		return this.idpEntityId;
	}
}
