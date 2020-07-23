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

import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.X509Certificate;
import javax.annotation.Nonnull;
import javax.annotation.Nullable;
import javax.crypto.SecretKey;

import net.shibboleth.utilities.java.support.annotation.constraint.NotEmpty;
import org.apache.xml.security.algorithms.JCEMapper;
import org.apache.xml.security.encryption.XMLCipherParameters;
import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.junit.Assert;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.profile.action.EventIds;
import org.opensaml.profile.context.EventContext;
import org.opensaml.profile.context.ProfileRequestContext;
import org.opensaml.saml.common.SAMLObjectBuilder;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.saml.saml2.core.Artifact;
import org.opensaml.saml.saml2.core.ArtifactResolve;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeQuery;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedID;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;

import static java.util.Arrays.asList;
import static org.opensaml.security.crypto.KeySupport.generateKey;

/**
 * <b>Copied from OpenSAML Source Code</b> Helper methods for creating/testing SAML 2
 * objects within profile action tests. When methods herein refer to mock objects they are
 * always objects that have been created via Mockito unless otherwise noted.
 */
public class OpenSamlActionTestingSupport {

	static {
		OpenSamlInitializationService.initialize();
	}

	/** ID used for all generated {@link Response} objects. */
	final static String REQUEST_ID = "request";

	/** ID used for all generated {@link Response} objects. */
	final static String RESPONSE_ID = "response";

	/** ID used for all generated {@link Assertion} objects. */
	final static String ASSERTION_ID = "assertion";

	static EncryptedAssertion encryptAssertion(Assertion assertion, X509Certificate certificate) {
		Encrypter encrypter = getEncrypter(certificate);
		try {
			Encrypter.KeyPlacement keyPlacement = Encrypter.KeyPlacement.valueOf("PEER");
			encrypter.setKeyPlacement(keyPlacement);
			return encrypter.encrypt(assertion);
		}
		catch (EncryptionException e) {
			throw new Saml2Exception("Unable to encrypt assertion.", e);
		}
	}

	static EncryptedID encryptNameId(NameID nameID, X509Certificate certificate) {
		Encrypter encrypter = getEncrypter(certificate);
		try {
			Encrypter.KeyPlacement keyPlacement = Encrypter.KeyPlacement.valueOf("PEER");
			encrypter.setKeyPlacement(keyPlacement);
			return encrypter.encrypt(nameID);
		}
		catch (EncryptionException e) {
			throw new Saml2Exception("Unable to encrypt nameID.", e);
		}
	}

	static Encrypter getEncrypter(X509Certificate certificate) {
		Credential credential = CredentialSupport.getSimpleCredential(certificate, null);
		final String dataAlgorithm = XMLCipherParameters.AES_256;
		final String keyAlgorithm = XMLCipherParameters.RSA_1_5;
		SecretKey secretKey = generateKeyFromURI(dataAlgorithm);
		BasicCredential dataCredential = new BasicCredential(secretKey);
		DataEncryptionParameters dataEncryptionParameters = new DataEncryptionParameters();
		dataEncryptionParameters.setEncryptionCredential(dataCredential);
		dataEncryptionParameters.setAlgorithm(dataAlgorithm);

		KeyEncryptionParameters keyEncryptionParameters = new KeyEncryptionParameters();
		keyEncryptionParameters.setEncryptionCredential(credential);
		keyEncryptionParameters.setAlgorithm(keyAlgorithm);

		Encrypter encrypter = new Encrypter(dataEncryptionParameters, asList(keyEncryptionParameters));

		return encrypter;
	}

	static SecretKey generateKeyFromURI(String algoURI) {
		try {
			String jceAlgorithmName = JCEMapper.getJCEKeyAlgorithmFromURI(algoURI);
			int keyLength = JCEMapper.getKeyLengthFromURI(algoURI);
			return generateKey(jceAlgorithmName, keyLength, null);
		}
		catch (NoSuchAlgorithmException | NoSuchProviderException e) {
			throw new Saml2Exception(e);
		}
	}

	/**
	 * Builds an empty response. The ID of the message is {@link #OUTBOUND_MSG_ID}, the
	 * issue instant is 1970-01-01T00:00:00Z and the SAML version is
	 * {@link SAMLVersion#VERSION_11}.
	 * @return the constructed response
	 */
	@Nonnull
	static Response buildResponse() {
		final SAMLObjectBuilder<Response> responseBuilder = (SAMLObjectBuilder<Response>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<Response>getBuilderOrThrow(Response.DEFAULT_ELEMENT_NAME);

		final Response response = responseBuilder.buildObject();
		response.setID(OUTBOUND_MSG_ID);
		response.setIssueInstant(DateTime.now());
		response.setVersion(SAMLVersion.VERSION_20);

		return response;
	}

	/**
	 * Builds an empty artifact response. The ID of the message is
	 * {@link #OUTBOUND_MSG_ID}, the issue instant is 1970-01-01T00:00:00Z and the SAML
	 * version is {@link SAMLVersion#VERSION_11}.
	 * @return the constructed response
	 */
	@Nonnull
	static ArtifactResponse buildArtifactResponse() {
		final SAMLObjectBuilder<ArtifactResponse> responseBuilder = (SAMLObjectBuilder<ArtifactResponse>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<ArtifactResponse>getBuilderOrThrow(ArtifactResponse.DEFAULT_ELEMENT_NAME);

		final ArtifactResponse response = responseBuilder.buildObject();
		response.setID(OUTBOUND_MSG_ID);
		response.setIssueInstant(DateTime.now());
		response.setVersion(SAMLVersion.VERSION_20);

		return response;
	}

	/**
	 * Builds an {@link LogoutRequest}. If a {@link NameID} is given, it will be added to
	 * the constructed {@link LogoutRequest}.
	 * @param name the NameID to add to the request
	 * @return the built request
	 */
	@Nonnull
	static LogoutRequest buildLogoutRequest(final @Nullable NameID name) {
		final SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<Issuer>getBuilderOrThrow(Issuer.DEFAULT_ELEMENT_NAME);

		final SAMLObjectBuilder<LogoutRequest> reqBuilder = (SAMLObjectBuilder<LogoutRequest>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<LogoutRequest>getBuilderOrThrow(LogoutRequest.DEFAULT_ELEMENT_NAME);

		final Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(INBOUND_MSG_ISSUER);

		final LogoutRequest req = reqBuilder.buildObject();
		req.setID(REQUEST_ID);
		req.setIssueInstant(DateTime.now());
		req.setIssuer(issuer);
		req.setVersion(SAMLVersion.VERSION_20);

		if (name != null) {
			req.setNameID(name);
		}

		return req;
	}

	/**
	 * Builds an empty logout response. The ID of the message is {@link #OUTBOUND_MSG_ID},
	 * the issue instant is 1970-01-01T00:00:00Z and the SAML version is
	 * {@link SAMLVersion#VERSION_11}.
	 * @return the constructed response
	 */
	@Nonnull
	static LogoutResponse buildLogoutResponse() {
		final SAMLObjectBuilder<LogoutResponse> responseBuilder = (SAMLObjectBuilder<LogoutResponse>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<LogoutResponse>getBuilderOrThrow(LogoutResponse.DEFAULT_ELEMENT_NAME);

		final LogoutResponse response = responseBuilder.buildObject();
		response.setID(OUTBOUND_MSG_ID);
		response.setIssueInstant(DateTime.now());
		response.setVersion(SAMLVersion.VERSION_20);

		return response;
	}

	/**
	 * Builds an empty assertion. The ID of the message is {@link #ASSERTION_ID}, the
	 * issue instant is 1970-01-01T00:00:00Z and the SAML version is
	 * {@link SAMLVersion#VERSION_11}.
	 * @return the constructed assertion
	 */
	@Nonnull
	static Assertion buildAssertion() {
		final SAMLObjectBuilder<Assertion> assertionBuilder = (SAMLObjectBuilder<Assertion>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<Assertion>getBuilderOrThrow(Assertion.DEFAULT_ELEMENT_NAME);

		final Assertion assertion = assertionBuilder.buildObject();
		assertion.setID(ASSERTION_ID);
		assertion.setIssueInstant(DateTime.now());
		assertion.setVersion(SAMLVersion.VERSION_20);

		return assertion;
	}

	@Nonnull
	static SubjectConfirmation buildSubjectConfirmation() {
		final SAMLObjectBuilder<SubjectConfirmation> subjectConfirmation = (SAMLObjectBuilder<SubjectConfirmation>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<SubjectConfirmation>getBuilderOrThrow(SubjectConfirmation.DEFAULT_ELEMENT_NAME);

		return subjectConfirmation.buildObject();
	}

	/**
	 * Builds an authentication statement. The authn instant is set to
	 * 1970-01-01T00:00:00Z.
	 * @return the constructed statement
	 */
	@Nonnull
	static AuthnStatement buildAuthnStatement() {
		final SAMLObjectBuilder<AuthnStatement> statementBuilder = (SAMLObjectBuilder<AuthnStatement>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<AuthnStatement>getBuilderOrThrow(AuthnStatement.DEFAULT_ELEMENT_NAME);

		final AuthnStatement statement = statementBuilder.buildObject();
		statement.setAuthnInstant(DateTime.now());

		return statement;
	}

	/**
	 * Builds an empty attribute statement.
	 * @return the constructed statement
	 */
	@Nonnull
	static AttributeStatement buildAttributeStatement() {
		final SAMLObjectBuilder<AttributeStatement> statementBuilder = (SAMLObjectBuilder<AttributeStatement>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<AttributeStatement>getBuilderOrThrow(AttributeStatement.DEFAULT_ELEMENT_NAME);

		final AttributeStatement statement = statementBuilder.buildObject();

		return statement;
	}

	/**
	 * Builds a {@link Subject}. If a principal name is given a {@link NameID}, whose
	 * value is the given principal name, will be created and added to the
	 * {@link Subject}.
	 * @param principalName the principal name to add to the subject
	 * @return the built subject
	 */
	@Nonnull
	static Subject buildSubject(final @Nullable String principalName) {
		final SAMLObjectBuilder<Subject> subjectBuilder = (SAMLObjectBuilder<Subject>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<Subject>getBuilderOrThrow(Subject.DEFAULT_ELEMENT_NAME);
		final Subject subject = subjectBuilder.buildObject();

		if (principalName != null) {
			subject.setNameID(buildNameID(principalName));
		}

		return subject;
	}

	@Nonnull
	static SubjectConfirmationData buildSubjectConfirmationData(String localSpEntityId) {
		final SAMLObjectBuilder<SubjectConfirmationData> subjectBuilder = (SAMLObjectBuilder<SubjectConfirmationData>) XMLObjectProviderRegistrySupport
				.getBuilderFactory()
				.<SubjectConfirmationData>getBuilderOrThrow(SubjectConfirmationData.DEFAULT_ELEMENT_NAME);
		final SubjectConfirmationData subject = subjectBuilder.buildObject();
		subject.setRecipient(localSpEntityId);
		subject.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		subject.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return subject;
	}

	@Nonnull
	static Conditions buildConditions() {
		final SAMLObjectBuilder<Conditions> subjectBuilder = (SAMLObjectBuilder<Conditions>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<Conditions>getBuilderOrThrow(Conditions.DEFAULT_ELEMENT_NAME);
		final Conditions conditions = subjectBuilder.buildObject();
		conditions.setNotBefore(DateTime.now().minus(Duration.millis(5 * 60 * 1000)));
		conditions.setNotOnOrAfter(DateTime.now().plus(Duration.millis(5 * 60 * 1000)));
		return conditions;
	}

	/**
	 * Builds a {@link NameID}.
	 * @param principalName the principal name to use in the NameID
	 * @return the built NameID
	 */
	@Nonnull
	static NameID buildNameID(final @Nonnull @NotEmpty String principalName) {
		final SAMLObjectBuilder<NameID> nameIdBuilder = (SAMLObjectBuilder<NameID>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<NameID>getBuilderOrThrow(NameID.DEFAULT_ELEMENT_NAME);
		final NameID nameId = nameIdBuilder.buildObject();
		nameId.setValue(principalName);
		return nameId;
	}

	/**
	 * Builds a {@link Issuer}.
	 * @param entityID the entity ID to use in the Issuer
	 * @return the built Issuer
	 */
	@Nonnull
	static Issuer buildIssuer(final @Nonnull @NotEmpty String entityID) {
		final SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<Issuer>getBuilderOrThrow(Issuer.DEFAULT_ELEMENT_NAME);
		final Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(entityID);
		return issuer;
	}

	/**
	 * Builds an {@link AttributeQuery}. If a {@link Subject} is given, it will be added
	 * to the constructed {@link AttributeQuery}.
	 * @param subject the subject to add to the query
	 * @return the built query
	 */
	@Nonnull
	static AttributeQuery buildAttributeQueryRequest(final @Nullable Subject subject) {
		final SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<Issuer>getBuilderOrThrow(Issuer.DEFAULT_ELEMENT_NAME);

		final SAMLObjectBuilder<AttributeQuery> queryBuilder = (SAMLObjectBuilder<AttributeQuery>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<AttributeQuery>getBuilderOrThrow(AttributeQuery.DEFAULT_ELEMENT_NAME);

		final Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(INBOUND_MSG_ISSUER);

		final AttributeQuery query = queryBuilder.buildObject();
		query.setID(REQUEST_ID);
		query.setIssueInstant(DateTime.now());
		query.setIssuer(issuer);
		query.setVersion(SAMLVersion.VERSION_20);

		if (subject != null) {
			query.setSubject(subject);
		}

		return query;
	}

	/**
	 * Builds an {@link AuthnRequest}.
	 * @return the built request
	 */
	@Nonnull
	static AuthnRequest buildAuthnRequest() {
		final SAMLObjectBuilder<Issuer> issuerBuilder = (SAMLObjectBuilder<Issuer>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<Issuer>getBuilderOrThrow(Issuer.DEFAULT_ELEMENT_NAME);

		final SAMLObjectBuilder<AuthnRequest> requestBuilder = (SAMLObjectBuilder<AuthnRequest>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<AuthnRequest>getBuilderOrThrow(AuthnRequest.DEFAULT_ELEMENT_NAME);

		final Issuer issuer = issuerBuilder.buildObject();
		issuer.setValue(INBOUND_MSG_ISSUER);

		final AuthnRequest request = requestBuilder.buildObject();
		request.setID(REQUEST_ID);
		request.setIssueInstant(DateTime.now());
		request.setIssuer(issuer);
		request.setVersion(SAMLVersion.VERSION_20);

		return request;
	}

	/**
	 * Builds a {@link ArtifactResolve}.
	 * @param artifact the artifact to add to the request
	 * @return the built request
	 */
	@Nonnull
	static ArtifactResolve buildArtifactResolve(final @Nullable String artifact) {
		final SAMLObjectBuilder<ArtifactResolve> requestBuilder = (SAMLObjectBuilder<ArtifactResolve>) XMLObjectProviderRegistrySupport
				.getBuilderFactory().<ArtifactResolve>getBuilderOrThrow(ArtifactResolve.DEFAULT_ELEMENT_NAME);
		final ArtifactResolve request = requestBuilder.buildObject();
		request.setID(REQUEST_ID);
		request.setIssueInstant(DateTime.now());
		request.setVersion(SAMLVersion.VERSION_11);

		if (artifact != null) {
			final SAMLObjectBuilder<Artifact> artifactBuilder = (SAMLObjectBuilder<Artifact>) XMLObjectProviderRegistrySupport
					.getBuilderFactory().<Artifact>getBuilderOrThrow(Artifact.DEFAULT_ELEMENT_NAME);
			final Artifact art = artifactBuilder.buildObject();
			art.setArtifact(artifact);
			request.setArtifact(art);
		}

		return request;
	}

	/** ID of the inbound message. */
	public final static String INBOUND_MSG_ID = "inbound";

	/** Issuer of the inbound message. */
	public final static String INBOUND_MSG_ISSUER = "http://sp.example.org";

	/** ID of the outbound message. */
	public final static String OUTBOUND_MSG_ID = "outbound";

	/** Issuer of the outbound message. */
	public final static String OUTBOUND_MSG_ISSUER = "http://idp.example.org";

	/**
	 * Checks that the request context contains an EventContext, and that the event
	 * content is as given.
	 * @param profileRequestContext the context to check
	 * @param event event to check
	 */
	static void assertEvent(@Nonnull final ProfileRequestContext profileRequestContext,
			@Nonnull final Object event) {
		EventContext ctx = profileRequestContext.getSubcontext(EventContext.class);
		Assert.assertNotNull(ctx);
		Assert.assertEquals(ctx.getEvent(), event);
	}

	/**
	 * Checks that the given request context does not contain an EventContext (thus
	 * signaling a "proceed" event).
	 * @param profileRequestContext the context to check
	 */
	static void assertProceedEvent(@Nonnull final ProfileRequestContext profileRequestContext) {
		EventContext<String> ctx = profileRequestContext.getSubcontext(EventContext.class);
		Assert.assertTrue(ctx == null || ctx.getEvent().equals(EventIds.PROCEED_EVENT_ID));
	}

}
