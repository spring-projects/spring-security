/*
 * Copyright 2002-2025 the original author or authors.
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

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Arrays;
import java.util.Map;
import java.util.Set;

import com.fasterxml.jackson.core.Base64Variants;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.cbor.CBORFactory;
import com.webauthn4j.converter.AttestationObjectConverter;
import com.webauthn4j.converter.util.ObjectConverter;
import com.webauthn4j.data.attestation.AttestationObject;
import com.webauthn4j.data.attestation.authenticator.AuthenticatorData;
import com.webauthn4j.data.extension.authenticator.RegistrationExtensionAuthenticatorOutput;
import org.assertj.core.api.recursive.comparison.RecursiveComparisonConfiguration;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.PasswordEncodedUser;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse;
import org.springframework.security.web.webauthn.api.AuthenticatorAttestationResponse.AuthenticatorAttestationResponseBuilder;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredentialRecord;
import org.springframework.security.web.webauthn.api.PublicKeyCredential;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.TestAuthenticatorAttestationResponses;
import org.springframework.security.web.webauthn.api.TestCredentialRecords;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentials;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.TestPublicKeyCredentialUserEntities;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;
import static org.assertj.core.api.Assertions.assertThatRuntimeException;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.verifyNoInteractions;

@ExtendWith(MockitoExtension.class)
class Webauthn4jRelyingPartyOperationsTests {

	@Mock
	private PublicKeyCredentialUserEntityRepository userEntities;

	@Mock
	private UserCredentialRepository userCredentials;

	// AuthenticatorDataFlags.Bitmasks
	private static byte UP = 0x01;

	private static byte UV = 0x04;

	private static byte BE = 0x08;

	private static byte BS = 0x10;

	private Set<String> origins = Set.of("https://example.localhost:8443");

	private UsernamePasswordAuthenticationToken user = new UsernamePasswordAuthenticationToken("user", "password",
			AuthorityUtils.createAuthorityList("ROLE_USER"));

	private PublicKeyCredentialRpEntity rpEntity = TestPublicKeyCredentialRpEntities.createRpEntity().build();

	private Webauthn4JRelyingPartyOperations rpOperations;

	@BeforeEach
	void setUp() {
		this.rpOperations = new Webauthn4JRelyingPartyOperations(this.userEntities, this.userCredentials, this.rpEntity,
				this.origins);
	}

	String label = "Phone";

	@Test
	void constructorWhenUserEntitiesNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new Webauthn4JRelyingPartyOperations(null, this.userCredentials, this.rpEntity, this.origins));
	}

	@Test
	void constructorWhenUserCredentialsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(
				() -> new Webauthn4JRelyingPartyOperations(this.userEntities, null, this.rpEntity, this.origins));
	}

	@Test
	void constructorWhenRpEntityNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new Webauthn4JRelyingPartyOperations(this.userEntities,
				this.userCredentials, null, this.origins));
	}

	@Test
	void constructorWhenOriginsNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> new Webauthn4JRelyingPartyOperations(this.userEntities,
				this.userCredentials, this.rpEntity, null));
	}

	@Test
	void createPublicKeyCredentialCreationOptionsWhenRequestNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.rpOperations.createPublicKeyCredentialCreationOptions(null));
	}

	@Test
	void createPublicKeyCredentialCreationOptionsWhenAnonymousThenIllegalArgumentException() {
		AnonymousAuthenticationToken anonymous = new AnonymousAuthenticationToken("key", "notAuthenticated",
				Set.of(() -> "ROLE_ANOYMOUS"));
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.rpOperations.createPublicKeyCredentialCreationOptions(
					new ImmutablePublicKeyCredentialCreationOptionsRequest(anonymous)));
	}

	@Test
	void createPublicKeyCredentialCreationOptionsWhenNotIsAuthenticatedThenIllegalArgumentException() {
		UsernamePasswordAuthenticationToken notAuthenticated = new UsernamePasswordAuthenticationToken("user",
				"password");
		assertThatIllegalArgumentException()
			.isThrownBy(() -> this.rpOperations.createPublicKeyCredentialCreationOptions(
					new ImmutablePublicKeyCredentialCreationOptionsRequest(notAuthenticated)));
	}

	@Test
	void createPublicKeyCredentialCreationOptionsWhenDefaultsThenSuccess() {
		PublicKeyCredentialCreationOptions expectedCreationOptions = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.rp(this.rpEntity)
			.user(TestPublicKeyCredentialUserEntities.userEntity().build())
			.build();
		PublicKeyCredentialCreationOptions creationOptions = this.rpOperations.createPublicKeyCredentialCreationOptions(
				new ImmutablePublicKeyCredentialCreationOptionsRequest(this.user));
		assertThat(creationOptions).usingRecursiveComparison()
			.ignoringFields("challenge", "user.id")
			.isEqualTo(expectedCreationOptions);
		// https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-rp
		assertThat(creationOptions.getRp()).isNotNull();
		assertThat(creationOptions.getRp().getName()).describedAs("Its value's name member is REQUIRED").isNotNull();
		// https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-user
		PublicKeyCredentialUserEntity userEntity = creationOptions.getUser();
		assertThat(userEntity).isNotNull();
		assertThat(userEntity.getName()).isNotNull();
		assertThat(userEntity.getDisplayName()).isNotNull();
		// https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialuserentity-id
		Bytes userId = userEntity.getId();
		assertThat(userId).isNotNull();
		assertThat(userId.getBytes()).describedAs("user id is a maximum size of 64 bytes").hasSizeLessThanOrEqualTo(64);
		assertThat(userId.getBytes())
			.describedAs("we want enough entropy in the user id, so it should be at least 16 bytes")
			.hasSizeGreaterThanOrEqualTo(16);

		Bytes challenge = creationOptions.getChallenge();
		assertThat(challenge).isNotNull();
		byte[] challengeBytes = challenge.getBytes();
		// https://www.w3.org/TR/webauthn-3/#sctn-cryptographic-challenges
		assertThat(challengeBytes).describedAs("Challenges should be at least 16 bytes")
			.hasSizeGreaterThanOrEqualTo(16);
		// https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-pubkeycredparams
		assertThat(creationOptions.getPubKeyCredParams()).describedAs(
				"Relying Parties that wish to support a wide range of authenticators SHOULD include at least the following COSEAlgorithmIdentifier values")
			.containsExactly(PublicKeyCredentialParameters.EdDSA, PublicKeyCredentialParameters.ES256,
					PublicKeyCredentialParameters.RS256);
	}

	@Test
	void createPublicKeyCredentialCreationOptionsWhenCustomizeThenCustomized() {
		Duration overriddenTimeout = Duration.ofMinutes(10);
		this.rpOperations.setCustomizeCreationOptions((options) -> options.timeout(overriddenTimeout));
		PublicKeyCredentialCreationOptions creationOptions = this.rpOperations.createPublicKeyCredentialCreationOptions(
				new ImmutablePublicKeyCredentialCreationOptionsRequest(this.user));
		assertThat(creationOptions.getTimeout()).isEqualTo(overriddenTimeout);
	}

	@Test
	void createPublicKeyCredentialCreationOptionsWhenExcludesThenSuccess() {
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntities.userEntity().build();
		CredentialRecord credentialRecord = TestCredentialRecords.userCredential().build();
		PublicKeyCredentialDescriptor descriptor = PublicKeyCredentialDescriptor.builder()
			.id(credentialRecord.getCredentialId())
			.transports(credentialRecord.getTransports())
			.build();
		given(this.userEntities.findByUsername(this.user.getName())).willReturn(userEntity);
		given(this.userCredentials.findByUserId(userEntity.getId())).willReturn(Arrays.asList(credentialRecord));
		PublicKeyCredentialCreationOptions creationOptions = this.rpOperations.createPublicKeyCredentialCreationOptions(
				new ImmutablePublicKeyCredentialCreationOptionsRequest(this.user));

		RecursiveComparisonConfiguration configuration = RecursiveComparisonConfiguration.builder().build();
		assertThat(creationOptions.getExcludeCredentials()).usingRecursiveFieldByFieldElementComparator(configuration)
			.containsOnly(descriptor);
	}

	// registerCredential

	@Test
	void registerCredentialWhenRpRegistrationRequestNullThenIllegalArgumentException() {
		assertThatIllegalArgumentException().isThrownBy(() -> this.rpOperations.registerCredential(null));
	}

	@Test
	void registerCredentialWhenDefaultTransportsThenSuccess() {
		PublicKeyCredentialCreationOptions creationOptions = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		PublicKeyCredential<AuthenticatorAttestationResponse> publicKeyCredential = TestPublicKeyCredentials
			.createPublicKeyCredential()
			.build();
		RelyingPartyPublicKey rpPublicKey = new RelyingPartyPublicKey(publicKeyCredential, this.label);

		ImmutableRelyingPartyRegistrationRequest rpRegistrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				creationOptions, rpPublicKey);
		CredentialRecord credentialRecord = this.rpOperations.registerCredential(rpRegistrationRequest);
		assertThat(credentialRecord).isNotNull();
		assertThat(credentialRecord.getCredentialId()).isNotNull();
		assertThat(credentialRecord.getTransports()).containsExactlyInAnyOrder(AuthenticatorTransport.INTERNAL,
				AuthenticatorTransport.HYBRID);
	}

	@Test
	void registerCredentialWhenInternalTransportThenCredentialRecordHasTransport() {
		PublicKeyCredentialCreationOptions creationOptions = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		AuthenticatorAttestationResponse response = TestAuthenticatorAttestationResponses
			.createAuthenticatorAttestationResponse()
			.transports(AuthenticatorTransport.INTERNAL)
			.build();
		PublicKeyCredential<AuthenticatorAttestationResponse> publicKeyCredential = TestPublicKeyCredentials
			.createPublicKeyCredential()
			.response(response)
			.build();
		RelyingPartyPublicKey rpPublicKey = new RelyingPartyPublicKey(publicKeyCredential, this.label);

		ImmutableRelyingPartyRegistrationRequest rpRegistrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				creationOptions, rpPublicKey);
		CredentialRecord credentialRecord = this.rpOperations.registerCredential(rpRegistrationRequest);
		assertThat(credentialRecord).isNotNull();
		assertThat(credentialRecord.getTransports()).containsExactlyInAnyOrder(AuthenticatorTransport.INTERNAL);
	}

	@Test
	void registerCredentialWhenExistsThenException() {
		PublicKeyCredentialCreationOptions creationOptions = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		PublicKeyCredential<AuthenticatorAttestationResponse> publicKeyCredential = TestPublicKeyCredentials
			.createPublicKeyCredential()
			.build();
		RelyingPartyPublicKey rpPublicKey = new RelyingPartyPublicKey(publicKeyCredential, this.label);

		ImmutableRelyingPartyRegistrationRequest rpRegistrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				creationOptions, rpPublicKey);
		given(this.userCredentials.findByCredentialId(publicKeyCredential.getRawId()))
			.willReturn(TestCredentialRecords.userCredential().build());
		assertThatRuntimeException().isThrownBy(() -> this.rpOperations.registerCredential(rpRegistrationRequest));
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 7. Verify that the value of C.type is webauthn.create.
	 */
	@Test
	void registerCredentialWhenCTypeIsNotWebAuthn() {
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		String originalClientDataJSON = new String(
				TestAuthenticatorAttestationResponses.createAuthenticatorAttestationResponse()
					.build()
					.getClientDataJSON()
					.getBytes());
		String invalidTypeClientDataJSON = originalClientDataJSON.replace("webauthn.create", "webauthn.INVALID");
		AuthenticatorAttestationResponseBuilder responseBldr = TestAuthenticatorAttestationResponses
			.createAuthenticatorAttestationResponse()
			.clientDataJSON(new Bytes(invalidTypeClientDataJSON.getBytes(StandardCharsets.UTF_8)));
		PublicKeyCredential publicKey = TestPublicKeyCredentials.createPublicKeyCredential(responseBldr.build()).build();
		ImmutableRelyingPartyRegistrationRequest registrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				options, new RelyingPartyPublicKey(publicKey, this.label));
		assertThatRuntimeException().isThrownBy(() -> this.rpOperations.registerCredential(registrationRequest))
			.withMessageContaining("ClientData.type");
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 8. Verify that the value of C.challengeBytes equals the base64url encoding of
	 * options.challengeBytes.
	 */
	@Test
	void registerCredentialWhenCChallengeNotEqualBase64UrlEncodingOptionsChallenge() {
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			// change the expected challenge so it does not match
			.challenge(Bytes.fromBase64("h0vgwGQjoCzAzDUsmzPpk-JVIJRRgn0L4KVSYNRcEZc"))
			.build();
		AuthenticatorAttestationResponseBuilder responseBldr = TestAuthenticatorAttestationResponses
			.createAuthenticatorAttestationResponse();
		PublicKeyCredential publicKey = TestPublicKeyCredentials.createPublicKeyCredential(responseBldr.build()).build();
		ImmutableRelyingPartyRegistrationRequest registrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				options, new RelyingPartyPublicKey(publicKey, this.label));

		assertThatRuntimeException().isThrownBy(() -> this.rpOperations.registerCredential(registrationRequest))
			.withMessageContaining("challenge");
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 9. Verify that the value of C.origin is an origin expected by the Relying Party.
	 * See 13.4.9 Validating the origin of a credential for guidance.
	 */
	@Test
	void registerCredentialWhenCOriginNotExpected() {
		this.rpOperations = new Webauthn4JRelyingPartyOperations(this.userEntities, this.userCredentials, this.rpEntity,
				Set.of("https://doesnotmatch.localhost:8443"));
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		AuthenticatorAttestationResponseBuilder responseBldr = TestAuthenticatorAttestationResponses
			.createAuthenticatorAttestationResponse();
		PublicKeyCredential publicKey = TestPublicKeyCredentials.createPublicKeyCredential(responseBldr.build()).build();
		ImmutableRelyingPartyRegistrationRequest registrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				options, new RelyingPartyPublicKey(publicKey, this.label));

		assertThatRuntimeException().isThrownBy(() -> this.rpOperations.registerCredential(registrationRequest))
			.withMessageContaining("origin");
	}

	// FIXME: Need to add 10. If C.topOrigin is present
	// https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 13. Verify that the rpIdHash in authData is the SHA-256 hash of the RP ID expected
	 * by the Relying Party.
	 */
	@Test
	void registerCredentialWhenClientDataJSONDoesNotMatchHash() {
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.rp(PublicKeyCredentialRpEntity.builder().id("invalid").name("Spring Security").build())
			.build();
		AuthenticatorAttestationResponseBuilder responseBldr = TestAuthenticatorAttestationResponses
			.createAuthenticatorAttestationResponse();
		PublicKeyCredential publicKey = TestPublicKeyCredentials.createPublicKeyCredential(responseBldr.build()).build();
		ImmutableRelyingPartyRegistrationRequest registrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				options, new RelyingPartyPublicKey(publicKey, this.label));

		assertThatRuntimeException().isThrownBy(() -> this.rpOperations.registerCredential(registrationRequest))
			.withMessageContaining("hash");
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 14. Verify that the UP bit of the flags in authData is set.
	 */
	@Test
	void registerCredentialWhenUPFlagsNotSet() throws Exception {
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();

		PublicKeyCredential publicKey = TestPublicKeyCredentials.createPublicKeyCredential(setFlag(UP)).build();
		ImmutableRelyingPartyRegistrationRequest registrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				options, new RelyingPartyPublicKey(publicKey, this.label));

		assertThatRuntimeException().isThrownBy(() -> this.rpOperations.registerCredential(registrationRequest))
			.withMessageContaining("UP flag");
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 15. If the Relying Party requires user verification for this registration, verify
	 * that the UV bit of the flags in authData is set.
	 */
	@Test
	void registerCredentialWhenUVBitNotSet() throws Exception {
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.authenticatorSelection(AuthenticatorSelectionCriteria.builder()
				.userVerification(UserVerificationRequirement.REQUIRED)
				.build())
			.build();
		PublicKeyCredential publicKey = TestPublicKeyCredentials.createPublicKeyCredential(setFlag(UV)).build();
		ImmutableRelyingPartyRegistrationRequest registrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				options, new RelyingPartyPublicKey(publicKey, this.label));

		assertThatRuntimeException().isThrownBy(() -> this.rpOperations.registerCredential(registrationRequest))
			.withMessageContaining("UV flag");
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 16. If the BE bit of the flags in authData is not set, verify that the BS bit is
	 * not set.
	 */
	@Test
	void registerCredentialWhenBENotSetAndBSSet() throws Exception {
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		PublicKeyCredential publicKey = TestPublicKeyCredentials.createPublicKeyCredential(setFlag(BE)).build();
		ImmutableRelyingPartyRegistrationRequest registrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				options, new RelyingPartyPublicKey(publicKey, this.label));

		assertThatRuntimeException().isThrownBy(() -> this.rpOperations.registerCredential(registrationRequest))
			.withMessageContaining("Backup state bit");
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 17. If the Relying Party uses the credential's backup eligibility to inform its
	 * user experience flows and/or policies, evaluate the BE bit of the flags in
	 * authData.
	 */
	@Test
	void registerCredentialWhenBEInformsUserExperienceBETrue() {
		// FIXME: Implement this
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 18. If the Relying Party uses the credential's backup state to inform its user
	 * experience flows and/or policies, evaluate the BS bit of the flags in authData.
	 */
	@Test
	void registerCredentialWhenBSInformsUserExperienceBSTrue() {
		// FIXME: Search for AuthenticatorDataFlags.BS to implement
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 19. Verify that the "alg" parameter in the credential public key in authData
	 * matches the alg attribute of one of the items in options.pubKeyCredParams.
	 */
	@Test
	void registerCredentialWhenAlgDoesNotMatchOptions() {
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.pubKeyCredParams(PublicKeyCredentialParameters.RS1)
			.build();
		PublicKeyCredential<AuthenticatorAttestationResponse> publicKey = TestPublicKeyCredentials
			.createPublicKeyCredential()
			.build();
		ImmutableRelyingPartyRegistrationRequest registrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				options, new RelyingPartyPublicKey(publicKey, this.label));

		assertThatRuntimeException().isThrownBy(() -> this.rpOperations.registerCredential(registrationRequest))
			.withMessageContaining("options.pubKeyCredParams");
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential
	 *
	 * 20. Verify that the values of the client extension outputs in
	 * clientExtensionResults and the authenticator extension outputs in the extensions in
	 * authData are as expected, considering the client extension input values that were
	 * given in options.extensions and any specific policy of the Relying Party regarding
	 * unsolicited extensions, i.e., those that were not specified as part of
	 * options.extensions. In the general case, the meaning of "are as expected" is
	 * specific to the Relying Party and which extensions are in use.
	 */
	@Test
	void registerCredentialWhenClientExtensionOutputsDoNotMatch() {
		// FIXME: Implement this
	}

	/**
	 * https://www.w3.org/TR/webauthn-3/#reg-ceremony-verify-attestation
	 *
	 * 22. Verify that attStmt is a correct attestation statement, conveying a valid
	 * attestation signature, by using the attestation statement format fmt's verification
	 * procedure given attStmt, authData and hash.
	 */
	@Test
	void registerCredentialWhenFmtNotValid() throws Exception {
		PublicKeyCredentialCreationOptions options = TestPublicKeyCredentialCreationOptions
			.createPublicKeyCredentialCreationOptions()
			.build();
		PublicKeyCredential publicKey = TestPublicKeyCredentials.createPublicKeyCredential() // setFmt("packed")
			.build();
		ImmutableRelyingPartyRegistrationRequest registrationRequest = new ImmutableRelyingPartyRegistrationRequest(
				options, new RelyingPartyPublicKey(publicKey, this.label));

		// FIXME: Implement this test
		// assertThatThrownBy(() ->
		// this.rpOperations.registerCredential(registrationRequest)).hasMessageContaining("Flag
		// combination is invalid");
	}

	@Test
	void createCredentialRequestOptionsThenUserVerificationSameAsCreation() {
		PublicKeyCredentialCreationOptions creationOptions = this.rpOperations.createPublicKeyCredentialCreationOptions(
				new ImmutablePublicKeyCredentialCreationOptionsRequest(this.user));
		PublicKeyCredentialRequestOptionsRequest createRequest = new ImmutablePublicKeyCredentialRequestOptionsRequest(
				this.user);
		PublicKeyCredentialRequestOptions credentialRequestOptions = this.rpOperations
			.createCredentialRequestOptions(createRequest);
		assertThat(credentialRequestOptions.getUserVerification())
			.isEqualTo(creationOptions.getAuthenticatorSelection().getUserVerification());
	}

	@Test
	void createCredentialRequestOptionsWhenAnonymousAuthentication() {
		AnonymousAuthenticationToken authentication = new AnonymousAuthenticationToken("key", "anonymousUser",
				Set.of(() -> "ROLE_ANONYMOUS"));
		PublicKeyCredentialRequestOptionsRequest createRequest = new ImmutablePublicKeyCredentialRequestOptionsRequest(
				authentication);
		PublicKeyCredentialRequestOptions credentialRequestOptions = this.rpOperations
			.createCredentialRequestOptions(createRequest);

		assertThat(credentialRequestOptions.getAllowCredentials()).isEmpty();
		// verify anonymous user not saved
		verifyNoInteractions(this.userEntities);
	}

	@Test
	void createCredentialRequestOptionsWhenNullAuthentication() {
		PublicKeyCredentialRequestOptionsRequest createRequest = new ImmutablePublicKeyCredentialRequestOptionsRequest(
				null);
		PublicKeyCredentialRequestOptions credentialRequestOptions = this.rpOperations
			.createCredentialRequestOptions(createRequest);

		assertThat(credentialRequestOptions.getAllowCredentials()).isEmpty();
		// verify anonymous user not saved
		verifyNoInteractions(this.userEntities);
	}

	@Test
	void createCredentialRequestOptionsWhenAuthenticated() {
		UserDetails user = PasswordEncodedUser.user();
		UsernamePasswordAuthenticationToken auth = new UsernamePasswordAuthenticationToken(user, null,
				user.getAuthorities());
		PublicKeyCredentialUserEntity userEntity = TestPublicKeyCredentialUserEntities.userEntity().build();
		CredentialRecord credentialRecord = TestCredentialRecords.userCredential().build();
		given(this.userEntities.findByUsername(user.getUsername())).willReturn(userEntity);
		given(this.userCredentials.findByUserId(userEntity.getId())).willReturn(Arrays.asList(credentialRecord));
		PublicKeyCredentialRequestOptionsRequest createRequest = new ImmutablePublicKeyCredentialRequestOptionsRequest(
				auth);
		PublicKeyCredentialRequestOptions credentialRequestOptions = this.rpOperations
			.createCredentialRequestOptions(createRequest);

		assertThat(credentialRequestOptions.getAllowCredentials()).extracting(PublicKeyCredentialDescriptor::getId)
			.containsExactly(credentialRecord.getCredentialId());
	}

	private static AuthenticatorAttestationResponse setFlag(byte... flags) throws Exception {
		AuthenticatorAttestationResponseBuilder authAttResponseBldr = TestAuthenticatorAttestationResponses
			.createAuthenticatorAttestationResponse();
		byte[] originalAttestationObjBytes = authAttResponseBldr.build().getAttestationObject().getBytes();
		ObjectMapper cbor = cbor();
		AttestationObjectConverter attestationObjectConverter = new AttestationObjectConverter(new ObjectConverter());
		ObjectNode attObj = (ObjectNode) cbor.readTree(originalAttestationObjBytes);

		byte[] rawAuthData = attObj.get("authData").binaryValue();

		for (byte flag : flags) {
			rawAuthData[32] ^= flag;
		}
		JsonNodeFactory f = JsonNodeFactory.instance;
		byte[] updatedAttObjBytes = cbor
			.writeValueAsBytes(attObj.setAll(Map.of("authData", f.binaryNode(rawAuthData))));

		AttestationObject attestationObject = attestationObjectConverter.convert(updatedAttObjBytes);
		AuthenticatorData<RegistrationExtensionAuthenticatorOutput> authenticatorData = attestationObject
			.getAuthenticatorData();
		boolean flagBE = authenticatorData.isFlagBE();
		boolean flagBS = authenticatorData.isFlagBS();
		authAttResponseBldr.attestationObject(new Bytes(updatedAttObjBytes));
		return authAttResponseBldr.build();
	}

	private static AuthenticatorAttestationResponse setFmt(String fmt) throws Exception {
		AuthenticatorAttestationResponseBuilder authAttResponseBldr = TestAuthenticatorAttestationResponses
			.createAuthenticatorAttestationResponse();
		byte[] originalAttestationObjBytes = authAttResponseBldr.build().getAttestationObject().getBytes();
		ObjectMapper cbor = cbor();
		ObjectNode attObj = (ObjectNode) cbor.readTree(originalAttestationObjBytes);
		JsonNodeFactory f = JsonNodeFactory.instance;
		byte[] updatedAttObjBytes = cbor.writeValueAsBytes(attObj.setAll(Map.of("fmt", f.textNode(fmt))));
		authAttResponseBldr.attestationObject(new Bytes(updatedAttObjBytes));
		return authAttResponseBldr.build();
	}

	private static ObjectMapper cbor() {
		return new ObjectMapper(new CBORFactory()).setBase64Variant(Base64Variants.MODIFIED_FOR_URL);
	}

}
