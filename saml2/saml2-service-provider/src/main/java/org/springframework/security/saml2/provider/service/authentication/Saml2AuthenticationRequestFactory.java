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

package org.springframework.security.saml2.provider.service.authentication;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialType;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;

import java.nio.charset.StandardCharsets;

import static org.springframework.security.saml2.provider.service.authentication.Saml2AuthenticationRequest.withAuthenticationRequestContext;
import static org.springframework.security.saml2.provider.service.authentication.Saml2Utils.samlDeflate;
import static org.springframework.security.saml2.provider.service.authentication.Saml2Utils.samlEncode;

/**
 * Component that generates AuthenticationRequest, <code>samlp:AuthnRequestType</code> XML, and accompanying
 * signature data.
 * as defined by https://www.oasis-open.org/committees/download.php/35711/sstc-saml-core-errata-2.0-wd-06-diff.pdf
 * Page 50, Line 2147
 *
 * @since 5.2
 */
public interface Saml2AuthenticationRequestFactory {

	/**
	 * Creates an authentication request from the Service Provider, sp, to the Identity Provider, idp.
	 * The authentication result is an XML string that may be signed, encrypted, both or neither.
	 * This method only returns the {@code SAMLRequest} string for the request, and for a complete
	 * set of data parameters please use {@link #createRedirectAuthenticationRequest(Saml2AuthenticationRequestContext)}
	 * or {@link #createPostAuthenticationRequest(Saml2AuthenticationRequestContext)}
	 *
	 * @param request information about the identity provider,
	 * the recipient of this authentication request and accompanying data
	 * @return XML data in the format of a String. This data may be signed, encrypted, both signed and encrypted with the
	 * signature embedded in the XML or neither signed and encrypted
	 * @throws Saml2Exception when a SAML library exception occurs
	 * @since 5.2
	 * @deprecated please use {@link #createRedirectAuthenticationRequest(Saml2AuthenticationRequestContext)}
	 * or {@link #createPostAuthenticationRequest(Saml2AuthenticationRequestContext)}
	 * This method will be removed in future versions of Spring Security
	 */
	@Deprecated
	String createAuthenticationRequest(Saml2AuthenticationRequest request);

	/**
	 * Creates all the necessary AuthNRequest parameters for a REDIRECT binding.
	 * If the {@link Saml2AuthenticationRequestContext} doesn't contain any {@link Saml2X509CredentialType#SIGNING} credentials
	 * the result will not contain any signatures.
	 * The data set will be signed and encoded for REDIRECT binding including the DEFLATE encoding.
	 * It will contain the following parameters to be sent as part of the query string:
	 * {@code SAMLRequest, RelayState, SigAlg, Signature}.
	 * <i>The default implementation, for sake of backwards compatibility, of this method returns the
	 * SAMLRequest message with an XML signature embedded, that should only be used for the{@link Saml2MessageBinding#POST}
	 * binding, but works over {@link Saml2MessageBinding#POST} with most providers.</i>
	 * @param context - information about the identity provider, the recipient of this authentication request and
	 * accompanying data
	 * @return a {@link Saml2RedirectAuthenticationRequest} object with applicable http parameters
	 * necessary to make the AuthNRequest over a POST or REDIRECT binding.
	 * All parameters will be SAML encoded/deflated, but escaped, ie URI encoded or encoded for Form Data.
	 * @throws Saml2Exception when a SAML library exception occurs
	 * @since 5.3
	 */
	default Saml2RedirectAuthenticationRequest createRedirectAuthenticationRequest(
			Saml2AuthenticationRequestContext context
	) {
		//backwards compatible with 5.2.x settings
		Saml2AuthenticationRequest.Builder resultBuilder = withAuthenticationRequestContext(context);
		String samlRequest = createAuthenticationRequest(resultBuilder.build());
		samlRequest = samlEncode(samlDeflate(samlRequest));
		return Saml2RedirectAuthenticationRequest.withAuthenticationRequestContext(context)
				.samlRequest(samlRequest)
				.build();
	}


	/**
	 * Creates all the necessary AuthNRequest parameters for a POST binding.
	 * If the {@link Saml2AuthenticationRequestContext} doesn't contain any {@link Saml2X509CredentialType#SIGNING} credentials
	 * the result will not contain any signatures.
	 * The data set will be signed and encoded for  POST binding and if applicable signed with XML signatures.
	 * will contain the following parameters to be sent as part of the form data: {@code SAMLRequest, RelayState}.
	 * <i>The default implementation of this method returns the SAMLRequest message with an XML signature embedded,
	 * that should only be used for the {@link Saml2MessageBinding#POST} binding.</i>
	 * @param context - information about the identity provider, the recipient of this authentication request and
	 * accompanying data
	 * @return a {@link Saml2PostAuthenticationRequest} object with applicable http parameters
	 * necessary to make the AuthNRequest over a POST binding.
	 * All parameters will be SAML encoded but not escaped for Form Data.
	 * @throws Saml2Exception when a SAML library exception occurs
	 * @since 5.3
	 */
	default Saml2PostAuthenticationRequest createPostAuthenticationRequest(
			Saml2AuthenticationRequestContext context
	) {
		//backwards compatible with 5.2.x settings
		Saml2AuthenticationRequest.Builder resultBuilder = withAuthenticationRequestContext(context);
		String samlRequest = createAuthenticationRequest(resultBuilder.build());
		samlRequest = samlEncode(samlRequest.getBytes(StandardCharsets.UTF_8));
		return Saml2PostAuthenticationRequest.withAuthenticationRequestContext(context)
				.samlRequest(samlRequest)
				.build();
	}

}
