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

import java.util.UUID;

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

final class TestSaml2AuthenticationObjects {
	private static OpenSamlImplementation saml = OpenSamlImplementation.getInstance();

	static Response response(String destination, String issuerEntityId) {
		Response response = saml.buildSamlObject(Response.DEFAULT_ELEMENT_NAME);
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
		Assertion assertion = saml.buildSamlObject(Assertion.DEFAULT_ELEMENT_NAME);
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
		Issuer issuer = saml.buildSamlObject(Issuer.DEFAULT_ELEMENT_NAME);
		issuer.setValue(entityId);
		return issuer;
	}

	static Subject subject(String principalName) {
		Subject subject = saml.buildSamlObject(Subject.DEFAULT_ELEMENT_NAME);

		if (principalName != null) {
			subject.setNameID(nameId(principalName));
		}

		return subject;
	}

	static NameID nameId(String principalName) {
		NameID nameId = saml.buildSamlObject(NameID.DEFAULT_ELEMENT_NAME);
		nameId.setValue(principalName);
		return nameId;
	}

	static SubjectConfirmation subjectConfirmation() {
		return saml.buildSamlObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);
	}

	static SubjectConfirmationData subjectConfirmationData(String recipient) {
		SubjectConfirmationData subject = saml.buildSamlObject(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		subject.setRecipient(recipient);
		subject.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		subject.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return subject;
	}

	static Conditions conditions() {
		Conditions conditions = saml.buildSamlObject(Conditions.DEFAULT_ELEMENT_NAME);
		conditions.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		conditions.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return conditions;
	}

}
