/*
 * Copyright 2002-2021 the original author or authors.
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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;
import net.shibboleth.utilities.java.support.resolver.CriteriaSet;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.metadata.criteria.role.impl.EvaluableProtocolRoleDescriptorCriterion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.criteria.impl.EvaluableEntityIDCredentialCriterion;
import org.opensaml.security.credential.criteria.impl.EvaluableUsageCredentialCriterion;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;

import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.core.Saml2ResponseValidatorResult;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.web.util.UriUtils;

/**
 * Utility methods for verifying SAML component signatures with OpenSAML
 *
 * For internal use only.
 *
 * @author Josh Cummings
 */

final class OpenSamlVerificationUtils {

	static VerifierPartial verifySignature(StatusResponseType object, RelyingPartyRegistration registration) {
		return new VerifierPartial(object, registration);
	}

	static VerifierPartial verifySignature(RequestAbstractType object, RelyingPartyRegistration registration) {
		return new VerifierPartial(object, registration);
	}

	static SignatureTrustEngine trustEngine(RelyingPartyRegistration registration) {
		Set<Credential> credentials = new HashSet<>();
		Collection<Saml2X509Credential> keys = registration.getAssertingPartyDetails().getVerificationX509Credentials();
		for (Saml2X509Credential key : keys) {
			BasicX509Credential cred = new BasicX509Credential(key.getCertificate());
			cred.setUsageType(UsageType.SIGNING);
			cred.setEntityId(registration.getAssertingPartyDetails().getEntityId());
			credentials.add(cred);
		}
		CredentialResolver credentialsResolver = new CollectionCredentialResolver(credentials);
		return new ExplicitKeySignatureTrustEngine(credentialsResolver,
				DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
	}

	private OpenSamlVerificationUtils() {

	}

	static class VerifierPartial {

		private final String id;

		private final CriteriaSet criteria;

		private final SignatureTrustEngine trustEngine;

		VerifierPartial(StatusResponseType object, RelyingPartyRegistration registration) {
			this.id = object.getID();
			this.criteria = verificationCriteria(object.getIssuer());
			this.trustEngine = trustEngine(registration);
		}

		VerifierPartial(RequestAbstractType object, RelyingPartyRegistration registration) {
			this.id = object.getID();
			this.criteria = verificationCriteria(object.getIssuer());
			this.trustEngine = trustEngine(registration);
		}

		Saml2ResponseValidatorResult redirect(HttpServletRequest request, String objectParameterName) {
			RedirectSignature signature = new RedirectSignature(request, objectParameterName);
			if (signature.getAlgorithm() == null) {
				return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Missing signature algorithm for object [" + this.id + "]"));
			}
			if (!signature.hasSignature()) {
				return Saml2ResponseValidatorResult.failure(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Missing signature for object [" + this.id + "]"));
			}
			Collection<Saml2Error> errors = new ArrayList<>();
			String algorithmUri = signature.getAlgorithm();
			try {
				if (!this.trustEngine.validate(signature.getSignature(), signature.getContent(), algorithmUri,
						this.criteria, null)) {
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
							"Invalid signature for object [" + this.id + "]"));
				}
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for object [" + this.id + "]: "));
			}
			return Saml2ResponseValidatorResult.failure(errors);
		}

		Saml2ResponseValidatorResult post(Signature signature) {
			Collection<Saml2Error> errors = new ArrayList<>();
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			try {
				profileValidator.validate(signature);
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for object [" + this.id + "]: "));
			}

			try {
				if (!this.trustEngine.validate(signature, this.criteria)) {
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
							"Invalid signature for object [" + this.id + "]"));
				}
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for object [" + this.id + "]: "));
			}

			return Saml2ResponseValidatorResult.failure(errors);
		}

		private CriteriaSet verificationCriteria(Issuer issuer) {
			CriteriaSet criteria = new CriteriaSet();
			criteria.add(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer.getValue())));
			criteria.add(new EvaluableProtocolRoleDescriptorCriterion(new ProtocolCriterion(SAMLConstants.SAML20P_NS)));
			criteria.add(new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
			return criteria;
		}

		private static class RedirectSignature {

			private final HttpServletRequest request;

			private final String objectParameterName;

			RedirectSignature(HttpServletRequest request, String objectParameterName) {
				this.request = request;
				this.objectParameterName = objectParameterName;
			}

			String getAlgorithm() {
				return this.request.getParameter(Saml2ParameterNames.SIG_ALG);
			}

			byte[] getContent() {
				if (this.request.getParameter(Saml2ParameterNames.RELAY_STATE) != null) {
					return String
							.format("%s=%s&%s=%s&%s=%s", this.objectParameterName,
									UriUtils.encode(this.request.getParameter(this.objectParameterName),
											StandardCharsets.ISO_8859_1),
									Saml2ParameterNames.RELAY_STATE,
									UriUtils.encode(this.request.getParameter(Saml2ParameterNames.RELAY_STATE),
											StandardCharsets.ISO_8859_1),
									Saml2ParameterNames.SIG_ALG,
									UriUtils.encode(getAlgorithm(), StandardCharsets.ISO_8859_1))
							.getBytes(StandardCharsets.UTF_8);
				}
				else {
					return String
							.format("%s=%s&%s=%s", this.objectParameterName,
									UriUtils.encode(this.request.getParameter(this.objectParameterName),
											StandardCharsets.ISO_8859_1),
									Saml2ParameterNames.SIG_ALG,
									UriUtils.encode(getAlgorithm(), StandardCharsets.ISO_8859_1))
							.getBytes(StandardCharsets.UTF_8);
				}
			}

			byte[] getSignature() {
				return Saml2Utils.samlDecode(this.request.getParameter(Saml2ParameterNames.SIGNATURE));
			}

			boolean hasSignature() {
				return this.request.getParameter(Saml2ParameterNames.SIGNATURE) != null;
			}

		}

	}

}
