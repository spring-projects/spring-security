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

package org.springframework.security.webauthn.options;

import com.webauthn4j.authenticator.Authenticator;
import com.webauthn4j.data.*;
import com.webauthn4j.data.client.Origin;
import com.webauthn4j.data.client.challenge.Challenge;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.webauthn.challenge.ChallengeRepository;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetails;
import org.springframework.security.webauthn.userdetails.WebAuthnUserDetailsService;
import org.springframework.security.webauthn.util.ServletUtil;
import org.springframework.util.Assert;

import javax.servlet.http.HttpServletRequest;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * An {@link OptionsProvider} implementation
 *
 * @author Yoshikazu Nojima
 */
public class OptionsProviderImpl implements OptionsProvider {

	//~ Instance fields
	// ================================================================================================
	private String rpId = null;
	private String rpName = null;
	private String rpIcon = null;
	private List<PublicKeyCredentialParameters> pubKeyCredParams = new ArrayList<>();
	private AuthenticatorSelectionCriteria authenticatorSelection = new AuthenticatorSelectionCriteria(null, false, UserVerificationRequirement.PREFERRED);
	private AttestationConveyancePreference attestation = AttestationConveyancePreference.NONE;
	private Long registrationTimeout = null;
	private Long authenticationTimeout = null;
	private RegistrationExtensionsOptionProvider registrationExtensions = new RegistrationExtensionsOptionProvider();
	private AuthenticationExtensionsOptionProvider authenticationExtensions = new AuthenticationExtensionsOptionProvider();

	private WebAuthnUserDetailsService userDetailsService;
	private ChallengeRepository challengeRepository;

	// ~ Constructors
	// ===================================================================================================

	public OptionsProviderImpl(WebAuthnUserDetailsService userDetailsService, ChallengeRepository challengeRepository) {

		Assert.notNull(userDetailsService, "userDetailsService must not be null");
		Assert.notNull(challengeRepository, "challengeRepository must not be null");

		this.userDetailsService = userDetailsService;
		this.challengeRepository = challengeRepository;
	}


	// ~ Methods
	// ========================================================================================================


	/**
	 * {@inheritDoc}
	 */
	@Override
	public AttestationOptions getAttestationOptions(HttpServletRequest request, String username, Challenge challenge) {

		PublicKeyCredentialUserEntity user;
		Collection<? extends Authenticator> authenticators;

		try {
			WebAuthnUserDetails userDetails = userDetailsService.loadUserByUsername(username);
			authenticators = userDetails.getAuthenticators();
			user = new PublicKeyCredentialUserEntity(userDetails.getUserHandle(), username, null);
		} catch (UsernameNotFoundException e) {
			authenticators = Collections.emptyList();
			user = null;
		}

		List<PublicKeyCredentialDescriptor> credentials = authenticators.stream()
				.map(authenticator -> new PublicKeyCredentialDescriptor(
						PublicKeyCredentialType.PUBLIC_KEY,
						authenticator.getAttestedCredentialData().getCredentialId(),
						null
				))
				.collect(Collectors.toList());

		PublicKeyCredentialRpEntity relyingParty = new PublicKeyCredentialRpEntity(getEffectiveRpId(request), rpName, rpIcon);
		if (challenge == null) {
			challenge = challengeRepository.loadOrGenerateChallenge(request);
		} else {
			challengeRepository.saveChallenge(challenge, request);
		}

		return new AttestationOptions(relyingParty, user, challenge, pubKeyCredParams, registrationTimeout,
				credentials, authenticatorSelection, attestation, registrationExtensions.provide(request));
	}

	public AssertionOptions getAssertionOptions(HttpServletRequest request, String username, Challenge challenge) {

		Collection<? extends Authenticator> authenticators;
		try {
			WebAuthnUserDetails userDetails = userDetailsService.loadUserByUsername(username);
			authenticators = userDetails.getAuthenticators();
		} catch (UsernameNotFoundException e) {
			authenticators = Collections.emptyList();
		}

		String effectiveRpId = getEffectiveRpId(request);

		List<PublicKeyCredentialDescriptor> credentials = authenticators.stream()
				.map(authenticator -> new PublicKeyCredentialDescriptor(
						PublicKeyCredentialType.PUBLIC_KEY,
						authenticator.getAttestedCredentialData().getCredentialId(),
						null
				))
				.collect(Collectors.toList());

		if (challenge == null) {
			challenge = challengeRepository.loadOrGenerateChallenge(request);
		} else {
			challengeRepository.saveChallenge(challenge, request);
		}

		return new AssertionOptions(challenge, authenticationTimeout, effectiveRpId, credentials, authenticationExtensions.provide(request));
	}


	/**
	 * returns effective rpId based on request origin and configured <code>rpId</code>.
	 *
	 * @param request request
	 * @return effective rpId
	 */
	public String getEffectiveRpId(HttpServletRequest request) {
		String effectiveRpId;
		if (this.rpId != null) {
			effectiveRpId = this.rpId;
		} else {
			Origin origin = ServletUtil.getOrigin(request);
			effectiveRpId = origin.getHost();
		}
		return effectiveRpId;
	}

	/**
	 * returns configured rpId
	 *
	 * @return rpId
	 */
	public String getRpId() {
		return rpId;
	}

	/**
	 * configures rpId
	 *
	 * @param rpId rpId
	 */
	public void setRpId(String rpId) {
		this.rpId = rpId;
	}

	/**
	 * returns rpName
	 *
	 * @return rpName
	 */
	public String getRpName() {
		return rpName;
	}

	/**
	 * configures rpName
	 *
	 * @param rpName rpName
	 */
	public void setRpName(String rpName) {
		Assert.hasText(rpName, "rpName parameter must not be empty or null");
		this.rpName = rpName;
	}

	/**
	 * returns rpIcon
	 *
	 * @return rpIcon
	 */
	public String getRpIcon() {
		return rpIcon;
	}

	/**
	 * configures rpIcon
	 *
	 * @param rpIcon rpIcon
	 */
	public void setRpIcon(String rpIcon) {
		Assert.hasText(rpIcon, "rpIcon parameter must not be empty or null");
		this.rpIcon = rpIcon;
	}

	/**
	 * returns {@link PublicKeyCredentialParameters} list
	 *
	 * @return {@link PublicKeyCredentialParameters} list
	 */
	public List<PublicKeyCredentialParameters> getPubKeyCredParams() {
		return pubKeyCredParams;
	}

	/**
	 * configures pubKeyCredParams
	 *
	 * @param pubKeyCredParams {@link PublicKeyCredentialParameters} list
	 */
	public void setPubKeyCredParams(List<PublicKeyCredentialParameters> pubKeyCredParams) {
		this.pubKeyCredParams = pubKeyCredParams;
	}

	/**
	 * returns the registration timeout
	 *
	 * @return the registration timeout
	 */
	public Long getRegistrationTimeout() {
		return registrationTimeout;
	}

	/**
	 * configures the registration timeout
	 *
	 * @param registrationTimeout registration timeout
	 */
	public void setRegistrationTimeout(Long registrationTimeout) {
		Assert.isTrue(registrationTimeout >= 0, "registrationTimeout must be within unsigned long.");
		this.registrationTimeout = registrationTimeout;
	}

	/**
	 * returns the authentication timeout
	 *
	 * @return the authentication timeout
	 */
	public Long getAuthenticationTimeout() {
		return authenticationTimeout;
	}

	/**
	 * configures the authentication timeout
	 *
	 * @param authenticationTimeout authentication timeout
	 */
	public void setAuthenticationTimeout(Long authenticationTimeout) {
		Assert.isTrue(registrationTimeout >= 0, "registrationTimeout must be within unsigned long.");
		this.authenticationTimeout = authenticationTimeout;
	}

	/**
	 * returns the {@link AuthenticatorSelectionCriteria}
	 *
	 * @return the {@link AuthenticatorSelectionCriteria}
	 */
	public AuthenticatorSelectionCriteria getAuthenticatorSelection() {
		return authenticatorSelection;
	}

	/**
	 * configures the {@link AuthenticatorSelectionCriteria}
	 *
	 * @param authenticatorSelection the {@link AuthenticatorSelectionCriteria}
	 */
	public void setAuthenticatorSelection(AuthenticatorSelectionCriteria authenticatorSelection) {
		this.authenticatorSelection = authenticatorSelection;
	}

	/**
	 * returns the {@link AttestationConveyancePreference}
	 *
	 * @return the {@link AttestationConveyancePreference}
	 */
	public AttestationConveyancePreference getAttestation() {
		return attestation;
	}

	/**
	 * configures the {@link AttestationConveyancePreference}
	 *
	 * @param attestation the {@link AttestationConveyancePreference}
	 */
	public void setAttestation(AttestationConveyancePreference attestation) {
		this.attestation = attestation;
	}

	public RegistrationExtensionsOptionProvider getRegistrationExtensions() {
		return registrationExtensions;
	}

	public AuthenticationExtensionsOptionProvider getAuthenticationExtensions() {
		return authenticationExtensions;
	}

}
