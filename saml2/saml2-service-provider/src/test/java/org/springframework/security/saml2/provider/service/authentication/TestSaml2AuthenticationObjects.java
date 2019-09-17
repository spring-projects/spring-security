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

package org.springframework.security.saml2.provider.service.authentication;

import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;

import java.util.UUID;

final class TestSaml2AuthenticationObjects {
	private static OpenSamlImplementation saml = OpenSamlImplementation.getInstance();

	static Response response(String destination, String issuerEntityId) {
		Response response = saml.buildSAMLObject(Response.class);
		response.setID("R"+UUID.randomUUID().toString());
		response.setIssueInstant(DateTime.now());
		response.setVersion(SAMLVersion.VERSION_20);
		response.setID("_" + UUID.randomUUID().toString());
		response.setDestination(destination);
		response.setIssuer(issuer(issuerEntityId));
		return response;
	}
	static Assertion assertion(
			String username,
			String issuerEntityId,
			String recipientEntityId,
			String recipientUri
	) {
		Assertion assertion = saml.buildSAMLObject(Assertion.class);
		assertion.setID("A"+ UUID.randomUUID().toString());
		assertion.setIssueInstant(DateTime.now());
		assertion.setVersion(SAMLVersion.VERSION_20);
		assertion.setIssueInstant(DateTime.now());
		assertion.setIssuer(issuer(issuerEntityId));
		assertion.setSubject(subject(username));
		assertion.setConditions(conditions());

		SubjectConfirmation subjectConfirmation = subjectConfirmation();
		subjectConfirmation.setMethod(SubjectConfirmation.METHOD_BEARER);
		SubjectConfirmationData confirmationData = subjectConfirmationData(recipientEntityId);
		confirmationData.setRecipient(recipientUri);
		subjectConfirmation.setSubjectConfirmationData(confirmationData);
		assertion.getSubject().getSubjectConfirmations().add(subjectConfirmation);
		return assertion;
	}


	static Issuer issuer(String entityId) {
		Issuer issuer = saml.buildSAMLObject(Issuer.class);
		issuer.setValue(entityId);
		return issuer;
	}

	static Subject subject(String principalName) {
		Subject subject = saml.buildSAMLObject(Subject.class);

		if (principalName != null) {
			subject.setNameID(nameId(principalName));
		}

		return subject;
	}

	static NameID nameId(String principalName) {
		NameID nameId = saml.buildSAMLObject(NameID.class);
		nameId.setValue(principalName);
		return nameId;
	}

	static SubjectConfirmation subjectConfirmation() {
		return saml.buildSAMLObject(SubjectConfirmation.class);
	}

	static SubjectConfirmationData subjectConfirmationData(String recipient) {
		SubjectConfirmationData subject = saml.buildSAMLObject(SubjectConfirmationData.class);
		subject.setRecipient(recipient);
		subject.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		subject.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return subject;
	}

	static Conditions conditions() {
		Conditions conditions = saml.buildSAMLObject(Conditions.class);
		conditions.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		conditions.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return conditions;
	}

}
