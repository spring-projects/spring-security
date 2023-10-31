/*
 * Copyright 2002-2022 the original author or authors.
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

import java.io.Serializable;
import java.nio.charset.Charset;

import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.util.Assert;

/**
 * Data holder for {@code AuthNRequest} parameters to be sent using either the
 * {@link Saml2MessageBinding#POST} or {@link Saml2MessageBinding#REDIRECT} binding. Data
 * will be encoded and possibly deflated, but will not be escaped for transport, ie URL
 * encoded, {@link org.springframework.web.util.UriUtils#encode(String, Charset)} or HTML
 * encoded, {@link org.springframework.web.util.HtmlUtils#htmlEscape(String)}.
 * https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * (line 2031)
 *
 * @since 5.3
 * @see Saml2PostAuthenticationRequest
 * @see Saml2RedirectAuthenticationRequest
 */
public abstract class AbstractSaml2AuthenticationRequest implements Serializable {

	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	private final String samlRequest;

	private final String relayState;

	private final String authenticationRequestUri;

	private final String relyingPartyRegistrationId;

	private final String id;

	/**
	 * Mandatory constructor for the {@link AbstractSaml2AuthenticationRequest}
	 * @param samlRequest - the SAMLRequest XML data, SAML encoded, cannot be empty or
	 * null
	 * @param relayState - RelayState value that accompanies the request, may be null
	 * @param authenticationRequestUri - The authenticationRequestUri, a URL, where to
	 * send the XML message, cannot be empty or null
	 * @param relyingPartyRegistrationId the registration id of the relying party, may be
	 * null
	 * @param id This is the unique id used in the {@link #samlRequest}, cannot be empty
	 * or null
	 */
	AbstractSaml2AuthenticationRequest(String samlRequest, String relayState, String authenticationRequestUri,
			String relyingPartyRegistrationId, String id) {
		Assert.hasText(samlRequest, "samlRequest cannot be null or empty");
		Assert.hasText(authenticationRequestUri, "authenticationRequestUri cannot be null or empty");
		this.authenticationRequestUri = authenticationRequestUri;
		this.samlRequest = samlRequest;
		this.relayState = relayState;
		this.relyingPartyRegistrationId = relyingPartyRegistrationId;
		this.id = id;
	}

	/**
	 * Returns the AuthNRequest XML value to be sent. This value is already encoded for
	 * transport. If {@link #getBinding()} is {@link Saml2MessageBinding#REDIRECT} the
	 * value is deflated and SAML encoded. If {@link #getBinding()} is
	 * {@link Saml2MessageBinding#POST} the value is SAML encoded.
	 * @return the SAMLRequest parameter value
	 */
	public String getSamlRequest() {
		return this.samlRequest;
	}

	/**
	 * Returns the RelayState value, if present in the parameters
	 * @return the RelayState value, or null if not available
	 */
	public String getRelayState() {
		return this.relayState;
	}

	/**
	 * Returns the URI endpoint that this AuthNRequest should be sent to.
	 * @return the URI endpoint for this message
	 */
	public String getAuthenticationRequestUri() {
		return this.authenticationRequestUri;
	}

	/**
	 * The identifier for the {@link RelyingPartyRegistration} associated with this
	 * request
	 * @return the {@link RelyingPartyRegistration} id
	 * @since 5.8
	 */
	public String getRelyingPartyRegistrationId() {
		return this.relyingPartyRegistrationId;
	}

	/**
	 * The unique identifier for this Authentication Request
	 * @return the Authentication Request identifier
	 * @since 5.8
	 */
	public String getId() {
		return this.id;
	}

	/**
	 * Returns the binding this AuthNRequest will be sent and encoded with. If
	 * {@link Saml2MessageBinding#REDIRECT} is used, the DEFLATE encoding will be
	 * automatically applied.
	 * @return the binding this message will be sent with.
	 */
	public abstract Saml2MessageBinding getBinding();

	/**
	 * A builder for {@link AbstractSaml2AuthenticationRequest} and its subclasses.
	 */
	public static class Builder<T extends Builder<T>> {

		String authenticationRequestUri;

		String samlRequest;

		String relayState;

		String relyingPartyRegistrationId;

		String id;

		/**
		 * @deprecated Use {@link #Builder(RelyingPartyRegistration)} instead
		 */
		@Deprecated
		protected Builder() {
		}

		/**
		 * Creates a new Builder with relying party registration
		 * @param registration the registration of the relying party.
		 * @sine 5.8
		 */
		protected Builder(RelyingPartyRegistration registration) {
			this.relyingPartyRegistrationId = registration.getRegistrationId();
		}

		/**
		 * Casting the return as the generic subtype, when returning itself
		 * @return this object
		 */
		@SuppressWarnings("unchecked")
		protected final T _this() {
			return (T) this;
		}

		/**
		 * Sets the {@code RelayState} parameter that will accompany this AuthNRequest
		 * @param relayState the relay state value, unencoded. if null or empty, the
		 * parameter will be removed from the map.
		 * @return this object
		 */
		public T relayState(String relayState) {
			this.relayState = relayState;
			return _this();
		}

		/**
		 * Sets the {@code SAMLRequest} parameter that will accompany this AuthNRequest
		 * @param samlRequest the SAMLRequest parameter.
		 * @return this object
		 */
		public T samlRequest(String samlRequest) {
			this.samlRequest = samlRequest;
			return _this();
		}

		/**
		 * Sets the {@code authenticationRequestUri}, a URL that will receive the
		 * AuthNRequest message
		 * @param authenticationRequestUri the relay state value, unencoded.
		 * @return this object
		 */
		public T authenticationRequestUri(String authenticationRequestUri) {
			this.authenticationRequestUri = authenticationRequestUri;
			return _this();
		}

		/**
		 * This is the unique id used in the {@link #samlRequest}
		 * @param id the SAML2 request id
		 * @return the {@link AbstractSaml2AuthenticationRequest.Builder} for further
		 * configurations
		 * @since 5.8
		 */
		public T id(String id) {
			Assert.notNull(id, "id cannot be null");
			this.id = id;
			return _this();
		}

	}

}
