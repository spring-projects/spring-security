/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.web.webauthn.registration;

import java.io.IOException;
import java.util.function.Supplier;

import com.fasterxml.jackson.databind.json.JsonMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.http.server.ServletServerHttpRequest;
import org.springframework.http.server.ServletServerHttpResponse;
import org.springframework.security.authorization.AuthorizationManager;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.SingleResultAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.context.SecurityContextHolderStrategy;
import org.springframework.security.web.servlet.util.matcher.PathPatternRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.jackson.WebauthnJackson2Module;
import org.springframework.security.web.webauthn.management.ImmutableRelyingPartyRegistrationRequest;
import org.springframework.security.web.webauthn.management.RelyingPartyPublicKey;
import org.springframework.security.web.webauthn.management.UserCredentialRepository;
import org.springframework.security.web.webauthn.management.WebAuthnRelyingPartyOperations;
import org.springframework.util.Assert;
import org.springframework.web.filter.OncePerRequestFilter;

/**
 * Authenticates {@code PublicKeyCredential<AuthenticatorAssertionResponse>} that is
 * parsed from the body of the {@link HttpServletRequest} using the
 * {@link #setConverter(HttpMessageConverter)}. An example request is provided below:
 *
 * <pre>
 * {
 * 	"publicKey": {
 * 		"credential": {
 * 			"id": "dYF7EGnRFFIXkpXi9XU2wg",
 * 			"rawId": "dYF7EGnRFFIXkpXi9XU2wg",
 * 			"response": {
 * 				"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YViUy9GqwTRaMpzVDbXq1dyEAXVOxrou08k22ggRC45MKNhdAAAAALraVWanqkAfvZZFYZpVEg0AEHWBexBp0RRSF5KV4vV1NsKlAQIDJiABIVggQjmrekPGzyqtoKK9HPUH-8Z2FLpoqkklFpFPQVICQ3IiWCD6I9Jvmor685fOZOyGXqUd87tXfvJk8rxj9OhuZvUALA",
 * 				"clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiSl9RTi10SFJYRWVKYjlNcUNrWmFPLUdOVmlibXpGVGVWMk43Z0ptQUdrQSIsIm9yaWdpbiI6Imh0dHBzOi8vZXhhbXBsZS5sb2NhbGhvc3Q6ODQ0MyIsImNyb3NzT3JpZ2luIjpmYWxzZX0",
 * 				"transports": [
 * 					"internal",
 * 					"hybrid"
 * 				]
 * 			},
 * 			"type": "public-key",
 * 			"clientExtensionResults": {},
 * 			"authenticatorAttachment": "platform"
 * 		},
 * 		"label": "1password"
 * }
 * </pre>
 *
 * @author Rob Winch
 * @since 6.4
 */
public class WebAuthnRegistrationFilter extends OncePerRequestFilter {

	static final String DEFAULT_REGISTER_CREDENTIAL_URL = "/webauthn/register";

	private static final Log logger = LogFactory.getLog(WebAuthnRegistrationFilter.class);

	private final WebAuthnRelyingPartyOperations rpOptions;

	private final UserCredentialRepository userCredentials;

	private SecurityContextHolderStrategy securityContextHolderStrategy = SecurityContextHolder
		.getContextHolderStrategy();

	private HttpMessageConverter<Object> converter = new MappingJackson2HttpMessageConverter(
			JsonMapper.builder().addModule(new WebauthnJackson2Module()).build());

	private PublicKeyCredentialCreationOptionsRepository creationOptionsRepository = new HttpSessionPublicKeyCredentialCreationOptionsRepository();

	private RequestMatcher registerCredentialMatcher = PathPatternRequestMatcher.withDefaults()
		.matcher(HttpMethod.POST, DEFAULT_REGISTER_CREDENTIAL_URL);

	private RequestMatcher removeCredentialMatcher = PathPatternRequestMatcher.withDefaults()
		.matcher(HttpMethod.DELETE, "/webauthn/register/{id}");

	private AuthorizationManager<Bytes> deleteCredentialAuthorizationManager = SingleResultAuthorizationManager
		.denyAll();

	public WebAuthnRegistrationFilter(UserCredentialRepository userCredentials,
			WebAuthnRelyingPartyOperations rpOptions) {
		Assert.notNull(userCredentials, "userCredentials must not be null");
		Assert.notNull(rpOptions, "rpOptions must not be null");
		this.userCredentials = userCredentials;
		this.rpOptions = rpOptions;
	}

	/**
	 * Sets the {@link RequestMatcher} to trigger this filter's the credential
	 * registration operation .
	 * <p/>
	 * By default, the {@link RequestMatcher} is {@code POST /webauthn/register}.
	 * @param registerCredentialMatcher the {@link RequestMatcher} to use
	 * @since 6.5
	 */
	public void setRegisterCredentialMatcher(RequestMatcher registerCredentialMatcher) {
		Assert.notNull(registerCredentialMatcher, "registerCredentialMatcher cannot be null");
		this.registerCredentialMatcher = registerCredentialMatcher;
	}

	/**
	 * Sets the {@link RequestMatcher} to trigger this filter's the credential removal
	 * operation .
	 * <p/>
	 * By default, the {@link RequestMatcher} is {@code DELETE /webauthn/register/{id}}.
	 * @param removeCredentialMatcher the {@link RequestMatcher} to use
	 * @since 6.5
	 */
	public void setRemoveCredentialMatcher(RequestMatcher removeCredentialMatcher) {
		Assert.notNull(removeCredentialMatcher, "removeCredentialMatcher cannot be null");
		this.removeCredentialMatcher = removeCredentialMatcher;
	}

	/**
	 * Sets the {@link AuthorizationManager} used to authorize the delete credential
	 * operation. The object being authorized is the credential id as {@link Bytes}. By
	 * default, all delete requests are denied.
	 *
	 * <p>
	 * Per the <a href="https://www.w3.org/TR/webauthn-3/#credential-id">WebAuthn
	 * specification</a>, a credential id must contain at least 16 bytes with at least 100
	 * bits of entropy, making it practically unguessable. The specification also advises
	 * that credential ids should be kept private, as exposing them can leak personally
	 * identifying information (see
	 * <a href="https://www.w3.org/TR/webauthn-3/#sctn-credential-id-privacy-leak">§
	 * 14.6.3 Privacy leak via credential IDs</a>). This {@link AuthorizationManager} is
	 * therefore intended as defense in depth: even if a credential id were somehow
	 * exposed, an unauthorized user could not delete another user's credential.
	 * @param deleteCredentialAuthorizationManager the {@link AuthorizationManager} to use
	 * @since 6.5.10
	 */
	public void setDeleteCredentialAuthorizationManager(
			AuthorizationManager<Bytes> deleteCredentialAuthorizationManager) {
		Assert.notNull(deleteCredentialAuthorizationManager, "deleteCredentialAuthorizationManager cannot be null");
		this.deleteCredentialAuthorizationManager = deleteCredentialAuthorizationManager;
	}

	/**
	 * Sets the {@link SecurityContextHolderStrategy} to use. The default is
	 * {@link SecurityContextHolder#getContextHolderStrategy()}.
	 * @param securityContextHolderStrategy the {@link SecurityContextHolderStrategy} to
	 * use
	 * @since 6.5.10
	 */
	public void setSecurityContextHolderStrategy(SecurityContextHolderStrategy securityContextHolderStrategy) {
		Assert.notNull(securityContextHolderStrategy, "securityContextHolderStrategy cannot be null");
		this.securityContextHolderStrategy = securityContextHolderStrategy;
	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		if (this.registerCredentialMatcher.matches(request)) {
			registerCredential(request, response);
			return;
		}
		RequestMatcher.MatchResult removeMatchResult = this.removeCredentialMatcher.matcher(request);
		if (removeMatchResult.isMatch()) {
			String id = removeMatchResult.getVariables().get("id");
			removeCredential(request, response, id);
			return;
		}
		filterChain.doFilter(request, response);
	}

	/**
	 * Set the {@link HttpMessageConverter} to read the
	 * {@link WebAuthnRegistrationRequest} and write the response. The default is
	 * {@link MappingJackson2HttpMessageConverter}.
	 * @param converter the {@link HttpMessageConverter} to use. Cannot be null.
	 */
	public void setConverter(HttpMessageConverter<Object> converter) {
		Assert.notNull(converter, "converter cannot be null");
		this.converter = converter;
	}

	/**
	 * Sets the {@link PublicKeyCredentialCreationOptionsRepository} to use. The default
	 * is {@link HttpSessionPublicKeyCredentialCreationOptionsRepository}.
	 * @param creationOptionsRepository the
	 * {@link PublicKeyCredentialCreationOptionsRepository} to use. Cannot be null.
	 */
	public void setCreationOptionsRepository(PublicKeyCredentialCreationOptionsRepository creationOptionsRepository) {
		Assert.notNull(creationOptionsRepository, "creationOptionsRepository cannot be null");
		this.creationOptionsRepository = creationOptionsRepository;
	}

	private void registerCredential(HttpServletRequest request, HttpServletResponse response) throws IOException {
		WebAuthnRegistrationRequest registrationRequest = readRegistrationRequest(request);
		if (registrationRequest == null) {
			response.setStatus(HttpStatus.BAD_REQUEST.value());
			return;
		}
		PublicKeyCredentialCreationOptions options = this.creationOptionsRepository.load(request);
		if (options == null) {
			response.setStatus(HttpStatus.BAD_REQUEST.value());
			return;
		}
		this.creationOptionsRepository.save(request, response, null);
		CredentialRecord credentialRecord = this.rpOptions.registerCredential(
				new ImmutableRelyingPartyRegistrationRequest(options, registrationRequest.getPublicKey()));
		SuccessfulUserRegistrationResponse registrationResponse = new SuccessfulUserRegistrationResponse(
				credentialRecord);
		ServletServerHttpResponse outputMessage = new ServletServerHttpResponse(response);
		this.converter.write(registrationResponse, MediaType.APPLICATION_JSON, outputMessage);
	}

	private WebAuthnRegistrationRequest readRegistrationRequest(HttpServletRequest request) {
		HttpInputMessage inputMessage = new ServletServerHttpRequest(request);
		try {
			return (WebAuthnRegistrationRequest) this.converter.read(WebAuthnRegistrationRequest.class, inputMessage);
		}
		catch (Exception ex) {
			logger.debug("Unable to parse WebAuthnRegistrationRequest", ex);
			return null;
		}
	}

	private void removeCredential(HttpServletRequest request, HttpServletResponse response, String id)
			throws IOException {
		Bytes credentialId = Bytes.fromBase64(id);
		Supplier<Authentication> authentication = () -> this.securityContextHolderStrategy.getContext()
			.getAuthentication();
		AuthorizationResult result = this.deleteCredentialAuthorizationManager.authorize(authentication, credentialId);
		if (result != null && !result.isGranted()) {
			response.setStatus(HttpStatus.FORBIDDEN.value());
			return;
		}
		this.userCredentials.delete(credentialId);
		response.setStatus(HttpStatus.NO_CONTENT.value());
	}

	static class WebAuthnRegistrationRequest {

		private RelyingPartyPublicKey publicKey;

		RelyingPartyPublicKey getPublicKey() {
			return this.publicKey;
		}

		void setPublicKey(RelyingPartyPublicKey publicKey) {
			this.publicKey = publicKey;
		}

	}

	public static class SuccessfulUserRegistrationResponse {

		private final CredentialRecord credentialRecord;

		SuccessfulUserRegistrationResponse(CredentialRecord credentialRecord) {
			this.credentialRecord = credentialRecord;
		}

		public boolean isSuccess() {
			return true;
		}

	}

}
