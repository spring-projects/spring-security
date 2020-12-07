/*
 * Copyright 2002-2020 the original author or authors.
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

package org.springframework.security.saml2.core;

import java.time.Clock;
import java.time.Instant;
import java.util.UUID;

import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.impl.AuthnRequestBuilder;

/**
 * A {@link AuthnRequestBuilder} that gives each {@link AuthnRequest} some reasonable
 * defaults.
 *
 * @author Josh Cummings
 * @since 5.5
 */
public final class SpringSecurityAuthnRequestBuilder extends AuthnRequestBuilder {

	private final XMLObjectBuilder<AuthnRequest> builder;

	private Clock clock = Clock.systemUTC();

	SpringSecurityAuthnRequestBuilder(XMLObjectBuilder<AuthnRequest> builder) {
		this.builder = builder;
	}

	/** {@inheritDoc} */
	@Override
	public AuthnRequest buildObject(final String namespaceURI, final String localName, final String namespacePrefix) {
		AuthnRequest authnRequest = this.builder.buildObject(namespaceURI, localName, namespacePrefix);
		setDefaults(authnRequest);
		return authnRequest;
	}

	/**
	 * Use this {@link Clock} with {@link Instant#now()} for generating timestamps
	 * @param clock
	 */
	public void setClock(Clock clock) {
		this.clock = clock;
	}

	private void setDefaults(AuthnRequest authnRequest) {
		if (authnRequest.getID() == null) {
			authnRequest.setID("ARQ" + UUID.randomUUID().toString().substring(1));
		}
		if (authnRequest.getIssueInstant() == null) {
			authnRequest.setIssueInstant(new DateTime(this.clock.millis()));
		}
		if (authnRequest.isForceAuthn() == null) {
			authnRequest.setForceAuthn(Boolean.FALSE);
		}
		if (authnRequest.isPassive() == null) {
			authnRequest.setIsPassive(Boolean.FALSE);
		}
		if (authnRequest.getProtocolBinding() == null) {
			authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
		}
	}

}
