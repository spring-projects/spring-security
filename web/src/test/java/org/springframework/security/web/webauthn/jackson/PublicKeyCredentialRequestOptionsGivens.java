package org.springframework.security.web.webauthn.jackson;

import org.springframework.security.web.webauthn.api.AuthenticatorTransport;
import org.springframework.security.web.webauthn.api.Bytes;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect;
import org.springframework.security.web.webauthn.api.CredProtectAuthenticationExtensionsClientInput.CredProtect.ProtectionPolicy;
import org.springframework.security.web.webauthn.api.ImmutableAuthenticationExtensionsClientInputs;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialDescriptor;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialRequestOptions;
import org.springframework.security.web.webauthn.api.PublicKeyCredentialType;
import org.springframework.security.web.webauthn.api.UserVerificationRequirement;

import java.time.Duration;
import java.util.List;
import java.util.Set;

/**
 * Object for {@code PublicKeyCredentialRequestOptions}
 *
 * @author Justin Cranford
 * @since 6.5
 */
public final class PublicKeyCredentialRequestOptionsGivens {
	private PublicKeyCredentialRequestOptionsGivens() {}

	public static PublicKeyCredentialRequestOptions create() {
		return PublicKeyCredentialRequestOptions.builder()
			.challenge(Bytes.random())
			.timeout(Duration.ofSeconds(60))
			.rpId("example.com")
			.allowCredentials(
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
			.userVerification(UserVerificationRequirement.PREFERRED)
			.extensions(
				new ImmutableAuthenticationExtensionsClientInputs(
					new CredProtectAuthenticationExtensionsClientInput(new CredProtect(ProtectionPolicy.USER_VERIFICATION_REQUIRED, true)),
					new MinPinLengthAuthenticationExtensionsClientInput(true)
				)
			)
			.build();
	}
}
