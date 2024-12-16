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

package org.springframework.security.web.webauthn.management;

import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.function.Consumer;
import java.util.stream.Collectors;

import com.webauthn4j.WebAuthnManager;
import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.authenticator.AuthenticatorImpl;
import com.webauthn4j.converter.util.CborConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.AuthenticationData;
import com.webauthn4j.data.AuthenticationParameters;
import com.webauthn4j.data.RegistrationData;
import com.webauthn4j.data.RegistrationParameters;
import com.webauthn4j.data.RegistrationRequest;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AttestedCredentialData;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.attestation.authenticator.COSEKey;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import com.webauthn4j.data.client.challenge.DefaultChallenge;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import com.webauthn4j.server.ServerProperty;

import org.springframework.security.authentication.AuthenticationTrustResolver;
import org.springframework.security.authentication.AuthenticationTrustResolverImpl;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.web.webauthn.api.AuthenticatorAssertionResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.ImmutableCredentialRecord;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCose;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions.PublicKeyCredentialCreationOptionsBuilder;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions.PublicKeyCredentialRequestOptionsBuilder;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;
import org.springframework.util.Assert;

/**
 * A <a href="https://webauthn4j.github.io/webauthn4j/en/">WebAuthn4j</a> implementation
 * of {@link WebAuthnRelyingPartyOperations}.
 *
 * @author Rob Winch
 * @since 6.4
 */
public class Webauthn4JRelyingPartyOperations implements WebAuthnRelyingPartyOperations {

	private final PublicKeyCredentialUserEntityRepository userEntities;

	private final UserCredentialRepository userCredentials;

	private final Set<String> allowedOrigins;

	private final PublicKeyCredentialRpEntity rp;

	private final ObjectConverter objectConverter = new ObjectConverter();

	private final AuthenticationTrustResolver trustResolver = new AuthenticationTrustResolverImpl();

	private WebAuthnManager webAuthnManager = WebAuthnManager.createNonStrictWebAuthnManager();

	private Consumer<PublicKeyCredentialCreationOptionsBuilder> customizeCreationOptions = (options) -> {
	};

	private Consumer<PublicKeyCredentialRequestOptionsBuilder> customizeRequestOptions = (options) -> {
	};

	/**
	 * Creates a new instance.
	 * @param userEntities the {@link PublicKeyCredentialUserEntityRepository} to use.
	 * @param userCredentials the {@link UserCredentialRepository} to use.
	 * @param rpEntity the {@link PublicKeyCredentialRpEntity} to use.
	 * @param allowedOrigins the allowed origins.
	 */
	public Webauthn4JRelyingPartyOperations(PublicKeyCredentialUserEntityRepository userEntities,
			UserCredentialRepository userCredentials, PublicKeyCredentialRpEntity rpEntity,
			Set<String> allowedOrigins) {
		Assert.notNull(userEntities, "userEntities cannot be null");
		Assert.notNull(userCredentials, "userCredentials cannot be null");
		Assert.notNull(rpEntity, "rpEntity cannot be null");
		Assert.notNull(allowedOrigins, "allowedOrigins cannot be null");
		this.userEntities = userEntities;
		this.userCredentials = userCredentials;
		this.rp = rpEntity;
		this.allowedOrigins = allowedOrigins;
	}

	/**
	 * Sets the {@link WebAuthnManager} to use. The default is
	 * {@link WebAuthnManager#createNonStrictWebAuthnManager()}
	 * @param webAuthnManager the {@link WebAuthnManager}.
	 */
	public void setWebAuthnManager(WebAuthnManager webAuthnManager) {
		Assert.notNull(webAuthnManager, "webAuthnManager cannot be null");
		this.webAuthnManager = webAuthnManager;
	}

	/**
	 * Sets a {@link Consumer} used to customize the
	 * {@link PublicKeyCredentialCreationOptionsBuilder} for
	 * {@link #createPublicKeyCredentialCreationOptions(PublicKeyCredentialCreationOptionsRequest)}.
	 * The default values are always populated, but can be overridden with this property.
	 * @param customizeCreationOptions the {@link Consumer} to customize the
	 * {@link PublicKeyCredentialCreationOptionsBuilder}
	 */
	public void setCustomizeCreationOptions(
			Consumer<PublicKeyCredentialCreationOptionsBuilder> customizeCreationOptions) {
		Assert.notNull(customizeCreationOptions, "customizeCreationOptions must not be null");
		this.customizeCreationOptions = customizeCreationOptions;
	}

	/**
	 * Sets a {@link Consumer} used to customize the
	 * {@link PublicKeyCredentialRequestOptionsBuilder} for
	 * {@link #createCredentialRequestOptions(PublicKeyCredentialRequestOptionsRequest)}.The
	 * default values are always populated, but can be overridden with this property.
	 * @param customizeRequestOptions the {@link Consumer} to customize the
	 * {@link PublicKeyCredentialRequestOptionsBuilder}
	 */
	public void setCustomizeRequestOptions(Consumer<PublicKeyCredentialRequestOptionsBuilder> customizeRequestOptions) {
		Assert.notNull(customizeRequestOptions, "customizeRequestOptions cannot be null");
		this.customizeRequestOptions = customizeRequestOptions;
	}

	@Override
	public PublicKeyCredentialCreationOptions createPublicKeyCredentialCreationOptions(
			PublicKeyCredentialCreationOptionsRequest request) {
		if (request == null) {
			throw new IllegalArgumentException("request cannot be null");
		}
		Authentication authentication = request.getAuthentication();
		if (!this.trustResolver.isAuthenticated(authentication)) {
			throw new IllegalArgumentException("Authentication must be authenticated");
		}
		AuthenticatorSelectionCriteria authenticatorSelection = AuthenticatorSelectionCriteria.builder()
			.userVerification(UserVerificationRequirement.PREFERRED)
			.residentKey(ResidentKeyRequirement.REQUIRED)
			.build();

		ImmutableAuthenticationExtensionsClientInputs clientInputs = new ImmutableAuthenticationExtensionsClientInputs(
				ImmutableAuthenticationExtensionsClientInput.credProps);

		PublicKeyCredentialUserEntity userEntity = findUserEntityOrCreateAndSave(authentication.getName());
		List<CredentialRecord> credentialRecords = this.userCredentials.findByUserId(userEntity.getId());

		PublicKeyCredentialCreationOptions options = PublicKeyCredentialCreationOptions.builder()
			.attestation(AttestationConveyancePreference.NONE)
			.pubKeyCredParams(PublicKeyCredentialParameters.EdDSA, PublicKeyCredentialParameters.ES256,
					PublicKeyCredentialParameters.RS256)
			.authenticatorSelection(authenticatorSelection)
			.challenge(Bytes.random())
			.extensions(clientInputs)
			.timeout(Duration.ofMinutes(5))
			.user(userEntity)
			.rp(this.rp)
			.excludeCredentials(credentialDescriptors(credentialRecords))
			.customize(this.customizeCreationOptions)
			.build();
		return options;
	}

	private static List<PublicKeyCredentialDescriptor> credentialDescriptors(List<CredentialRecord> credentialRecords) {
		List result = new ArrayList();
		for (CredentialRecord credentialRecord : credentialRecords) {
			Bytes id = Bytes.fromBase64(credentialRecord.getCredentialId().toBase64UrlString());
			PublicKeyCredentialDescriptor credentialDescriptor = PublicKeyCredentialDescriptor.builder()
				.id(id)
				.transports(credentialRecord.getTransports())
				.build();
			result.add(credentialDescriptor);
		}
		return result;
	}

	private PublicKeyCredentialUserEntity findUserEntityOrCreateAndSave(String username) {
		final PublicKeyCredentialUserEntity foundUserEntity = this.userEntities.findByUsername(username);
		if (foundUserEntity != null) {
			return foundUserEntity;
		}

		PublicKeyCredentialUserEntity userEntity = ImmutablePublicKeyCredentialUserEntity.builder()
			.displayName(username)
			.id(Bytes.random())
			.name(username)
			.build();
		this.userEntities.save(userEntity);
		return userEntity;
	}

	@Override
	public CredentialRecord registerCredential(RelyingPartyRegistrationRequest rpRegistrationRequest) {
		Assert.notNull(rpRegistrationRequest, "rpRegistrationRequest cannot be null");
		Bytes credentialId = rpRegistrationRequest.getPublicKey().getCredential().getRawId();
		CredentialRecord existingCredential = this.userCredentials.findByCredentialId(credentialId);
		if (existingCredential != null) {
			throw new IllegalArgumentException("Credential with id " + credentialId + " already exists");
		}
		PublicKeyCredentialCreationOptions creationOptions = rpRegistrationRequest.getCreationOptions();
		String rpId = creationOptions.getRp().getId();
		RelyingPartyPublicKey publicKey = rpRegistrationRequest.getPublicKey();
		PublicKeyCredential<AuthenticatorAttestationResponse> credential = publicKey.getCredential();
		AuthenticatorAttestationResponse response = credential.getResponse();
		// Server properties
		Set<Origin> origins = toOrigins();
		byte[] base64Challenge = creationOptions.getChallenge().getBytes();
		byte[] attestationObject = response.getAttestationObject().getBytes();
		byte[] clientDataJSON = response.getClientDataJSON().getBytes();
		Challenge challenge = new DefaultChallenge(base64Challenge);
		byte[] tokenBindingId = null /* set tokenBindingId */; // FIXME:
																// https://www.w3.org/TR/webauthn-1/#dom-collectedclientdata-tokenbinding
		ServerProperty serverProperty = new ServerProperty(origins, rpId, challenge, tokenBindingId);
		boolean userVerificationRequired = creationOptions.getAuthenticatorSelection()
			.getUserVerification() == UserVerificationRequirement.REQUIRED;
		// requireUserPresence The constant Boolean value true
		// https://www.w3.org/TR/webauthn-3/#sctn-op-make-cred
		boolean userPresenceRequired = true;
		List<com.webauthn4j.data.PublicKeyCredentialParameters> pubKeyCredParams = convertCredentialParamsToWebauthn4j(
				creationOptions.getPubKeyCredParams());
		Set<String> transports = convertTransportsToString(response);
		RegistrationRequest webauthn4jRegistrationRequest = new RegistrationRequest(attestationObject, clientDataJSON,
				transports);
		RegistrationParameters registrationParameters = new RegistrationParameters(serverProperty, pubKeyCredParams,
				userVerificationRequired, userPresenceRequired);
		RegistrationData registrationData = this.webAuthnManager.validate(webauthn4jRegistrationRequest,
				registrationParameters);
		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authData = registrationData.getAttestationObject()
			.getAuthenticatorData();

		CborConverter cborConverter = this.objectConverter.getCborConverter();
		COSEKey coseKey = authData.getAttestedCredentialData().getCOSEKey();
		byte[] rawCoseKey = cborConverter.writeValueAsBytes(coseKey);
		ImmutableCredentialRecord userCredential = ImmutableCredentialRecord.builder()
			.userEntityUserId(creationOptions.getUser().getId())
			.credentialType(credential.getType())
			.credentialId(credential.getRawId())
			.publicKey(new ImmutablePublicKeyCose(rawCoseKey))
			.signatureCount(authData.getSignCount())
			.uvInitialized(authData.isFlagUV())
			.transports(convertTransports(registrationData.getTransports()))
			.backupEligible(authData.isFlagBE())
			.backupState(authData.isFlagBS())
			.label(publicKey.getLabel())
			.attestationClientDataJSON(credential.getResponse().getClientDataJSON())
			.attestationObject(credential.getResponse().getAttestationObject())
			.build();
		this.userCredentials.save(userCredential);
		return userCredential;
	}

	private static Set<String> convertTransportsToString(AuthenticatorAttestationResponse response) {
		if (response.getTransports() == null) {
			return null;
		}
		Set<String> transports = new HashSet<>(response.getTransports().size());
		for (AuthenticatorTransport transport : response.getTransports()) {
			transports.add(transport.getValue());
		}
		return transports;
	}

	private List<com.webauthn4j.data.PublicKeyCredentialParameters> convertCredentialParamsToWebauthn4j(
			List<PublicKeyCredentialParameters> parameters) {
		return parameters.stream().map(this::convertParamToWebauthn4j).collect(Collectors.toUnmodifiableList());
	}

	private com.webauthn4j.data.PublicKeyCredentialParameters convertParamToWebauthn4j(
			PublicKeyCredentialParameters parameter) {
		if (parameter.getType() != PublicKeyCredentialType.PUBLIC_KEY) {
			throw new IllegalArgumentException(
					"Cannot convert unknown credential type " + parameter.getType() + " to webauthn4j");
		}
		long algValue = parameter.getAlg().getValue();
		com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier alg = com.webauthn4j.data.attestation.statement.COSEAlgorithmIdentifier
			.create(algValue);
		return new com.webauthn4j.data.PublicKeyCredentialParameters(
				com.webauthn4j.data.PublicKeyCredentialType.PUBLIC_KEY, alg);
	}

	private Set<Origin> toOrigins() {
		return this.allowedOrigins.stream().map(Origin::new).collect(Collectors.toSet());
	}

	private static Set<AuthenticatorTransport> convertTransports(
			Set<com.webauthn4j.data.AuthenticatorTransport> transports) {
		if (transports == null) {
			return Collections.emptySet();
		}
		return transports.stream()
			.map((t) -> AuthenticatorTransport.valueOf(t.getValue()))
			.collect(Collectors.toUnmodifiableSet());
	}

	@Override
	public PublicKeyCredentialRequestOptions createCredentialRequestOptions(
			PublicKeyCredentialRequestOptionsRequest request) {
		Authentication authentication = request.getAuthentication();
		// FIXME: do not load credentialRecords if anonymous
		PublicKeyCredentialUserEntity userEntity = findUserEntityOrCreateAndSave(authentication.getName());
		List<CredentialRecord> credentialRecords = this.userCredentials.findByUserId(userEntity.getId());
		return PublicKeyCredentialRequestOptions.builder()
			.allowCredentials(credentialDescriptors(credentialRecords))
			.challenge(Bytes.random())
			.rpId(this.rp.getId())
			.timeout(Duration.ofMinutes(5))
			.userVerification(UserVerificationRequirement.PREFERRED)
			.customize(this.customizeRequestOptions)
			.build();
	}

	@Override
	public PublicKeyCredentialUserEntity authenticate(RelyingPartyAuthenticationRequest request) {
		PublicKeyCredentialRequestOptions requestOptions = request.getRequestOptions();
		AuthenticatorAssertionResponse assertionResponse = request.getPublicKey().getResponse();
		Bytes keyId = request.getPublicKey().getRawId();
		CredentialRecord credentialRecord = this.userCredentials.findByCredentialId(keyId);

		CborConverter cborConverter = this.objectConverter.getCborConverter();
		AttestationObject attestationObject = cborConverter
			.readValue(credentialRecord.getAttestationObject().getBytes(), AttestationObject.class);

		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authData = attestationObject.getAuthenticatorData();
		AttestedCredentialData data = new AttestedCredentialData(authData.getAttestedCredentialData().getAaguid(),
				keyId.getBytes(), authData.getAttestedCredentialData().getCOSEKey());

		Authenticator authenticator = new AuthenticatorImpl(data, attestationObject.getAttestationStatement(),
				credentialRecord.getSignatureCount());
		if (authenticator == null) {
			throw new IllegalStateException("No authenticator found");
		}
		Set<Origin> origins = toOrigins();
		Challenge challenge = new DefaultChallenge(requestOptions.getChallenge().getBytes());
		// FIXME: should populate this
		byte[] tokenBindingId = null /* set tokenBindingId */;
		ServerProperty serverProperty = new ServerProperty(origins, requestOptions.getRpId(), challenge,
				tokenBindingId);
		boolean userVerificationRequired = request.getRequestOptions()
			.getUserVerification() == UserVerificationRequirement.REQUIRED;

		com.webauthn4j.data.AuthenticationRequest authenticationRequest = new com.webauthn4j.data.AuthenticationRequest(
				request.getPublicKey().getId().getBytes(), assertionResponse.getAuthenticatorData().getBytes(),
				assertionResponse.getClientDataJSON().getBytes(), assertionResponse.getSignature().getBytes());
		AuthenticationParameters authenticationParameters = new AuthenticationParameters(serverProperty, authenticator,
				userVerificationRequired);

		AuthenticationData authenticationData = this.webAuthnManager.validate(authenticationRequest,
				authenticationParameters);

		long updatedSignCount = authenticationData.getAuthenticatorData().getSignCount();
		ImmutableCredentialRecord updatedRecord = ImmutableCredentialRecord.fromCredentialRecord(credentialRecord)
			.lastUsed(Instant.now())
			.signatureCount(updatedSignCount)
			.build();
		this.userCredentials.save(updatedRecord);

		return this.userEntities.findById(credentialRecord.getUserEntityUserId());
	}

}
