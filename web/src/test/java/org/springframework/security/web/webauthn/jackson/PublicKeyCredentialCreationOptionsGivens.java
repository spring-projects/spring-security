package org.springframework.security.web.webauthn.jackson;

import org.springframework.security.web.webauthn.api.AttestationConveyancePreference;
import org.springframework.security.web.webauthn.api.AuthenticatorAttachment;
import org.springframework.security.web.webauthn.api.AuthenticatorSelectionCriteria;
import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.ImmutablePublicKeyCredentialUserEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialCreationOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialParameters;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRpEntity;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.ResidentKeyRequirement;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Object for {@code PublicKeyCredentialCreationOptions}
 *
 * @author Justin Cranford
 * @since 6.5
 */
public final class PublicKeyCredentialCreationOptionsGivens {
	private PublicKeyCredentialCreationOptionsGivens() {}

	public static PublicKeyCredentialCreationOptions create() {
		return PublicKeyCredentialCreationOptions.builder()
			.rp(
				PublicKeyCredentialRpEntity.builder()
					.id("example.com")
					.name("Example RP")
					.build()
			)
			.user(
				ImmutablePublicKeyCredentialUserEntity.builder()
					.name("name")
					.id(Bytes.random())
					.displayName("displayName")
					.build()
			)
			.challenge(Bytes.random())
			.pubKeyCredParams(
				List.of(
					PublicKeyCredentialParameters.EdDSA,
					PublicKeyCredentialParameters.ES256,
					PublicKeyCredentialParameters.ES384,
					PublicKeyCredentialParameters.ES512,
					PublicKeyCredentialParameters.RS256,
					PublicKeyCredentialParameters.RS384,
					PublicKeyCredentialParameters.RS512,
					PublicKeyCredentialParameters.RS1
				)
			)
			.timeout(Duration.ofSeconds(60))
			.excludeCredentials(
				List.of(
					PublicKeyCredentialDescriptor.builder()
						.id(Bytes.random())
						.type(PublicKeyCredentialType.PUBLIC_KEY)
						.transports(Set.of(AuthenticatorTransport.USB))
						.build(),
					PublicKeyCredentialDescriptor.builder()
						.id(Bytes.random())
						.type(PublicKeyCredentialType.PUBLIC_KEY)
						.transports(Set.of(AuthenticatorTransport.NFC))
						.build(),
					PublicKeyCredentialDescriptor.builder()
						.id(Bytes.random())
						.type(PublicKeyCredentialType.PUBLIC_KEY)
						.transports(Set.of(AuthenticatorTransport.BLE))
						.build(),
					PublicKeyCredentialDescriptor.builder()
						.id(Bytes.random())
						.type(PublicKeyCredentialType.PUBLIC_KEY)
						.transports(Set.of(AuthenticatorTransport.SMART_CARD))
						.build(),
					PublicKeyCredentialDescriptor.builder()
						.id(Bytes.random())
						.type(PublicKeyCredentialType.PUBLIC_KEY)
						.transports(Set.of(AuthenticatorTransport.HYBRID))
						.build(),
					PublicKeyCredentialDescriptor.builder()
						.id(Bytes.random())
						.type(PublicKeyCredentialType.PUBLIC_KEY)
						.transports(Set.of(AuthenticatorTransport.INTERNAL))
						.build()
				)
			)
			.authenticatorSelection(
				AuthenticatorSelectionCriteria.builder()
					.userVerification(UserVerificationRequirement.PREFERRED)
					.residentKey(ResidentKeyRequirement.REQUIRED)
					.authenticatorAttachment(AuthenticatorAttachment.PLATFORM)
					.build()
			)
			.attestation(AttestationConveyancePreference.DIRECT)
			.extensions(
				new ImmutableAuthenticationExtensionsClientInputs(
					new CredProtectAuthenticationExtensionsClientInput(new CredProtect(ProtectionPolicy.USER_VERIFICATION_REQUIRED, true)),
					new MinPinLengthAuthenticationExtensionsClientInput(true)
				)
			)
			.build();
	}
}
