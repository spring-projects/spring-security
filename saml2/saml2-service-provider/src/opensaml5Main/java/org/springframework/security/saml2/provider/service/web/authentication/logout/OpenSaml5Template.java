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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.xml.namespace.QName;

import net.shibboleth.shared.resolver.CriteriaSet;
import net.shibboleth.shared.xml.SerializeSupport;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.opensaml.core.criterion.EntityIdCriterion;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilder;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.util.XMLObjectSupport;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.criterion.ProtocolCriterion;
import org.opensaml.saml.ext.saml2delrestrict.Delegate;
import org.opensaml.saml.ext.saml2delrestrict.DelegationRestrictionType;
import org.opensaml.saml.metadata.criteria.role.impl.EvaluableProtocolRoleDescriptorCriterion;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.Condition;
import org.opensaml.saml.saml2.core.EncryptedAssertion;
import org.opensaml.saml.saml2.core.EncryptedAttribute;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.RequestAbstractType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.StatusResponseType;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.encryption.Decrypter;
import org.opensaml.saml.saml2.encryption.EncryptedElementTypeEncryptedKeyResolver;
import org.opensaml.saml.security.impl.SAMLMetadataSignatureSigningParametersResolver;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.SecurityException;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.credential.CredentialResolver;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.credential.UsageType;
import org.opensaml.security.credential.criteria.impl.EvaluableEntityIDCredentialCriterion;
import org.opensaml.security.credential.criteria.impl.EvaluableUsageCredentialCriterion;
import org.opensaml.security.credential.impl.CollectionCredentialResolver;
import org.opensaml.security.criteria.UsageCriterion;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.SignatureSigningParametersResolver;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.criterion.SignatureSigningConfigurationCriterion;
import org.opensaml.xmlsec.crypto.XMLSigningUtil;
import org.opensaml.xmlsec.encryption.support.ChainingEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.DecryptionException;
import org.opensaml.xmlsec.encryption.support.EncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.InlineEncryptedKeyResolver;
import org.opensaml.xmlsec.encryption.support.SimpleRetrievalMethodEncryptedKeyResolver;
import org.opensaml.xmlsec.impl.BasicSignatureSigningConfiguration;
import org.opensaml.xmlsec.keyinfo.KeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.KeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.keyinfo.impl.CollectionKeyInfoCredentialResolver;
import org.opensaml.xmlsec.keyinfo.impl.X509KeyInfoGeneratorFactory;
import org.opensaml.xmlsec.signature.SignableXMLObject;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureSupport;
import org.opensaml.xmlsec.signature.support.SignatureTrustEngine;
import org.opensaml.xmlsec.signature.support.impl.ExplicitKeySignatureTrustEngine;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.Saml2Error;
import org.springframework.security.saml2.core.Saml2ErrorCodes;
import org.springframework.security.saml2.core.Saml2ParameterNames;
import org.springframework.security.saml2.core.Saml2X509Credential;
import org.springframework.util.Assert;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

/**
 * For internal use only. Subject to breaking changes at any time.
 */
final class OpenSaml5Template implements OpenSamlOperations {

	private static final Log logger = LogFactory.getLog(OpenSaml5Template.class);

	@Override
	public <T extends XMLObject> T build(QName elementName) {
		XMLObjectBuilder<?> builder = XMLObjectProviderRegistrySupport.getBuilderFactory().getBuilder(elementName);
		if (builder == null) {
			throw new Saml2Exception("Unable to resolve Builder for " + elementName);
		}
		return (T) builder.buildObject(elementName);
	}

	@Override
	public <T extends XMLObject> T deserialize(String serialized) {
		return deserialize(new ByteArrayInputStream(serialized.getBytes(StandardCharsets.UTF_8)));
	}

	@Override
	public <T extends XMLObject> T deserialize(InputStream serialized) {
		try {
			Document document = XMLObjectProviderRegistrySupport.getParserPool().parse(serialized);
			Element element = document.getDocumentElement();
			UnmarshallerFactory factory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
			Unmarshaller unmarshaller = factory.getUnmarshaller(element);
			if (unmarshaller == null) {
				throw new Saml2Exception("Unsupported element of type " + element.getTagName());
			}
			return (T) unmarshaller.unmarshall(element);
		}
		catch (Saml2Exception ex) {
			throw ex;
		}
		catch (Exception ex) {
			throw new Saml2Exception("Failed to deserialize payload", ex);
		}
	}

	@Override
	public OpenSaml5SerializationConfigurer serialize(XMLObject object) {
		Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
		try {
			return serialize(marshaller.marshall(object));
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

	@Override
	public OpenSaml5SerializationConfigurer serialize(Element element) {
		return new OpenSaml5SerializationConfigurer(element);
	}

	@Override
	public OpenSaml5SignatureConfigurer withSigningKeys(Collection<Saml2X509Credential> credentials) {
		return new OpenSaml5SignatureConfigurer(credentials);
	}

	@Override
	public OpenSaml5VerificationConfigurer withVerificationKeys(Collection<Saml2X509Credential> credentials) {
		return new OpenSaml5VerificationConfigurer(credentials);
	}

	@Override
	public OpenSaml5DecryptionConfigurer withDecryptionKeys(Collection<Saml2X509Credential> credentials) {
		return new OpenSaml5DecryptionConfigurer(credentials);
	}

	OpenSaml5Template() {

	}

	static final class OpenSaml5SerializationConfigurer
			implements SerializationConfigurer<OpenSaml5SerializationConfigurer> {

		private final Element element;

		boolean pretty;

		OpenSaml5SerializationConfigurer(Element element) {
			this.element = element;
		}

		@Override
		public OpenSaml5SerializationConfigurer prettyPrint(boolean pretty) {
			this.pretty = pretty;
			return this;
		}

		@Override
		public String serialize() {
			if (this.pretty) {
				return SerializeSupport.prettyPrintXML(this.element);
			}
			return SerializeSupport.nodeToString(this.element);
		}

	}

	static final class OpenSaml5SignatureConfigurer implements SignatureConfigurer<OpenSaml5SignatureConfigurer> {

		private final Collection<Saml2X509Credential> credentials;

		private final Map<String, String> components = new LinkedHashMap<>();

		private List<String> algs = List.of(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

		OpenSaml5SignatureConfigurer(Collection<Saml2X509Credential> credentials) {
			this.credentials = credentials;
		}

		@Override
		public OpenSaml5SignatureConfigurer algorithms(List<String> algs) {
			this.algs = algs;
			return this;
		}

		@Override
		public <O extends SignableXMLObject> O sign(O object) {
			SignatureSigningParameters parameters = resolveSigningParameters();
			try {
				SignatureSupport.signObject(object, parameters);
			}
			catch (Exception ex) {
				throw new Saml2Exception(ex);
			}
			return object;
		}

		@Override
		public Map<String, String> sign(Map<String, String> params) {
			SignatureSigningParameters parameters = resolveSigningParameters();
			this.components.putAll(params);
			Credential credential = parameters.getSigningCredential();
			String algorithmUri = parameters.getSignatureAlgorithm();
			this.components.put(Saml2ParameterNames.SIG_ALG, algorithmUri);
			UriComponentsBuilder builder = UriComponentsBuilder.newInstance();
			for (Map.Entry<String, String> component : this.components.entrySet()) {
				builder.queryParam(component.getKey(),
						UriUtils.encode(component.getValue(), StandardCharsets.ISO_8859_1));
			}
			String queryString = builder.build(true).toString().substring(1);
			try {
				byte[] rawSignature = XMLSigningUtil.signWithURI(credential, algorithmUri,
						queryString.getBytes(StandardCharsets.UTF_8));
				String b64Signature = Saml2Utils.samlEncode(rawSignature);
				this.components.put(Saml2ParameterNames.SIGNATURE, b64Signature);
			}
			catch (SecurityException ex) {
				throw new Saml2Exception(ex);
			}
			return this.components;
		}

		private SignatureSigningParameters resolveSigningParameters() {
			List<Credential> credentials = resolveSigningCredentials();
			List<String> digests = Collections.singletonList(SignatureConstants.ALGO_ID_DIGEST_SHA256);
			String canonicalization = SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS;
			SignatureSigningParametersResolver resolver = new SAMLMetadataSignatureSigningParametersResolver();
			BasicSignatureSigningConfiguration signingConfiguration = new BasicSignatureSigningConfiguration();
			signingConfiguration.setSigningCredentials(credentials);
			signingConfiguration.setSignatureAlgorithms(this.algs);
			signingConfiguration.setSignatureReferenceDigestMethods(digests);
			signingConfiguration.setSignatureCanonicalizationAlgorithm(canonicalization);
			signingConfiguration.setKeyInfoGeneratorManager(buildSignatureKeyInfoGeneratorManager());
			CriteriaSet criteria = new CriteriaSet(new SignatureSigningConfigurationCriterion(signingConfiguration));
			try {
				SignatureSigningParameters parameters = resolver.resolveSingle(criteria);
				Assert.notNull(parameters, "Failed to resolve any signing credential");
				return parameters;
			}
			catch (Exception ex) {
				throw new Saml2Exception(ex);
			}
		}

		private NamedKeyInfoGeneratorManager buildSignatureKeyInfoGeneratorManager() {
			final NamedKeyInfoGeneratorManager namedManager = new NamedKeyInfoGeneratorManager();

			namedManager.setUseDefaultManager(true);
			final KeyInfoGeneratorManager defaultManager = namedManager.getDefaultManager();

			// Generator for X509Credentials
			final X509KeyInfoGeneratorFactory x509Factory = new X509KeyInfoGeneratorFactory();
			x509Factory.setEmitEntityCertificate(true);
			x509Factory.setEmitEntityCertificateChain(true);

			defaultManager.registerFactory(x509Factory);

			return namedManager;
		}

		private List<Credential> resolveSigningCredentials() {
			List<Credential> credentials = new ArrayList<>();
			for (Saml2X509Credential x509Credential : this.credentials) {
				X509Certificate certificate = x509Credential.getCertificate();
				PrivateKey privateKey = x509Credential.getPrivateKey();
				BasicCredential credential = CredentialSupport.getSimpleCredential(certificate, privateKey);
				credential.setUsageType(UsageType.SIGNING);
				credentials.add(credential);
			}
			return credentials;
		}

	}

	static final class OpenSaml5VerificationConfigurer implements VerificationConfigurer {

		private final Collection<Saml2X509Credential> credentials;

		private String entityId;

		OpenSaml5VerificationConfigurer(Collection<Saml2X509Credential> credentials) {
			this.credentials = credentials;
		}

		@Override
		public VerificationConfigurer entityId(String entityId) {
			this.entityId = entityId;
			return this;
		}

		private SignatureTrustEngine trustEngine(Collection<Saml2X509Credential> keys) {
			Set<Credential> credentials = new HashSet<>();
			for (Saml2X509Credential key : keys) {
				BasicX509Credential cred = new BasicX509Credential(key.getCertificate());
				cred.setUsageType(UsageType.SIGNING);
				cred.setEntityId(this.entityId);
				credentials.add(cred);
			}
			CredentialResolver credentialsResolver = new CollectionCredentialResolver(credentials);
			return new ExplicitKeySignatureTrustEngine(credentialsResolver,
					DefaultSecurityConfigurationBootstrap.buildBasicInlineKeyInfoCredentialResolver());
		}

		private CriteriaSet verificationCriteria(Issuer issuer) {
			return new CriteriaSet(new EvaluableEntityIDCredentialCriterion(new EntityIdCriterion(issuer.getValue())),
					new EvaluableProtocolRoleDescriptorCriterion(new ProtocolCriterion(SAMLConstants.SAML20P_NS)),
					new EvaluableUsageCredentialCriterion(new UsageCriterion(UsageType.SIGNING)));
		}

		@Override
		public Collection<Saml2Error> verify(SignableXMLObject signable) {
			if (signable instanceof StatusResponseType response) {
				return verifySignature(response.getID(), response.getIssuer(), response.getSignature());
			}
			if (signable instanceof RequestAbstractType request) {
				return verifySignature(request.getID(), request.getIssuer(), request.getSignature());
			}
			if (signable instanceof Assertion assertion) {
				return verifySignature(assertion.getID(), assertion.getIssuer(), assertion.getSignature());
			}
			throw new Saml2Exception("Unsupported object of type: " + signable.getClass().getName());
		}

		private Collection<Saml2Error> verifySignature(String id, Issuer issuer, Signature signature) {
			SignatureTrustEngine trustEngine = trustEngine(this.credentials);
			CriteriaSet criteria = verificationCriteria(issuer);
			Collection<Saml2Error> errors = new ArrayList<>();
			SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
			try {
				profileValidator.validate(signature);
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for object [" + id + "]: "));
			}

			try {
				if (!trustEngine.validate(signature, criteria)) {
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
							"Invalid signature for object [" + id + "]"));
				}
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for object [" + id + "]: "));
			}

			return errors;
		}

		@Override
		public Collection<Saml2Error> verify(RedirectParameters parameters) {
			SignatureTrustEngine trustEngine = trustEngine(this.credentials);
			CriteriaSet criteria = verificationCriteria(parameters.getIssuer());
			if (parameters.getAlgorithm() == null) {
				return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Missing signature algorithm for object [" + parameters.getId() + "]"));
			}
			if (!parameters.hasSignature()) {
				return Collections.singletonList(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Missing signature for object [" + parameters.getId() + "]"));
			}
			Collection<Saml2Error> errors = new ArrayList<>();
			String algorithmUri = parameters.getAlgorithm();
			try {
				if (!trustEngine.validate(parameters.getSignature(), parameters.getContent(), algorithmUri, criteria,
						null)) {
					errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
							"Invalid signature for object [" + parameters.getId() + "]"));
				}
			}
			catch (Exception ex) {
				errors.add(new Saml2Error(Saml2ErrorCodes.INVALID_SIGNATURE,
						"Invalid signature for object [" + parameters.getId() + "]: "));
			}
			return errors;
		}

	}

	static final class OpenSaml5DecryptionConfigurer implements DecryptionConfigurer {

		private static final EncryptedKeyResolver encryptedKeyResolver = new ChainingEncryptedKeyResolver(
				Arrays.asList(new InlineEncryptedKeyResolver(), new EncryptedElementTypeEncryptedKeyResolver(),
						new SimpleRetrievalMethodEncryptedKeyResolver()));

		private final Decrypter decrypter;

		OpenSaml5DecryptionConfigurer(Collection<Saml2X509Credential> decryptionCredentials) {
			this.decrypter = decrypter(decryptionCredentials);
		}

		private static Decrypter decrypter(Collection<Saml2X509Credential> decryptionCredentials) {
			Collection<Credential> credentials = new ArrayList<>();
			for (Saml2X509Credential key : decryptionCredentials) {
				Credential cred = CredentialSupport.getSimpleCredential(key.getCertificate(), key.getPrivateKey());
				credentials.add(cred);
			}
			KeyInfoCredentialResolver resolver = new CollectionKeyInfoCredentialResolver(credentials);
			Decrypter decrypter = new Decrypter(null, resolver, encryptedKeyResolver);
			decrypter.setRootInNewDocument(true);
			return decrypter;
		}

		@Override
		public void decrypt(XMLObject object) {
			if (object instanceof Response response) {
				decryptResponse(response);
				return;
			}
			if (object instanceof Assertion assertion) {
				decryptAssertion(assertion);
			}
			if (object instanceof LogoutRequest request) {
				decryptLogoutRequest(request);
			}
		}

		/*
		 * The methods that follow are adapted from OpenSAML's {@link DecryptAssertions},
		 * {@link DecryptNameIDs}, and {@link DecryptAttributes}.
		 *
		 * <p>The reason that these OpenSAML classes are not used directly is because they
		 * reference {@link javax.servlet.http.HttpServletRequest} which is a lower
		 * Servlet API version than what Spring Security SAML uses.
		 *
		 * If OpenSAML 5 updates to {@link jakarta.servlet.http.HttpServletRequest}, then
		 * this arrangement can be revisited.
		 */

		private void decryptResponse(Response response) {
			Collection<Assertion> decrypteds = new ArrayList<>();
			Collection<EncryptedAssertion> encrypteds = new ArrayList<>();

			int count = 0;
			int size = response.getEncryptedAssertions().size();
			for (EncryptedAssertion encrypted : response.getEncryptedAssertions()) {
				logger.trace(String.format("Decrypting EncryptedAssertion (%d/%d) in Response [%s]", count, size,
						response.getID()));
				try {
					Assertion decrypted = this.decrypter.decrypt(encrypted);
					if (decrypted != null) {
						encrypteds.add(encrypted);
						decrypteds.add(decrypted);
					}
					count++;
				}
				catch (DecryptionException ex) {
					throw new Saml2Exception(ex);
				}
			}

			response.getEncryptedAssertions().removeAll(encrypteds);
			response.getAssertions().addAll(decrypteds);

			// Re-marshall the response so that any ID attributes within the decrypted
			// Assertions
			// will have their ID-ness re-established at the DOM level.
			if (!decrypteds.isEmpty()) {
				try {
					XMLObjectSupport.marshall(response);
				}
				catch (final MarshallingException ex) {
					throw new Saml2Exception(ex);
				}
			}
		}

		private void decryptAssertion(Assertion assertion) {
			for (AttributeStatement statement : assertion.getAttributeStatements()) {
				decryptAttributes(statement);
			}
			decryptSubject(assertion.getSubject());
			if (assertion.getConditions() != null) {
				for (Condition c : assertion.getConditions().getConditions()) {
					if (!(c instanceof DelegationRestrictionType delegation)) {
						continue;
					}
					for (Delegate d : delegation.getDelegates()) {
						if (d.getEncryptedID() != null) {
							try {
								NameID decrypted = (NameID) this.decrypter.decrypt(d.getEncryptedID());
								if (decrypted != null) {
									d.setNameID(decrypted);
									d.setEncryptedID(null);
								}
							}
							catch (DecryptionException ex) {
								throw new Saml2Exception(ex);
							}
						}
					}
				}
			}
		}

		private void decryptAttributes(AttributeStatement statement) {
			Collection<Attribute> decrypteds = new ArrayList<>();
			Collection<EncryptedAttribute> encrypteds = new ArrayList<>();
			for (EncryptedAttribute encrypted : statement.getEncryptedAttributes()) {
				try {
					Attribute decrypted = this.decrypter.decrypt(encrypted);
					if (decrypted != null) {
						encrypteds.add(encrypted);
						decrypteds.add(decrypted);
					}
				}
				catch (Exception ex) {
					throw new Saml2Exception(ex);
				}
			}
			statement.getEncryptedAttributes().removeAll(encrypteds);
			statement.getAttributes().addAll(decrypteds);
		}

		private void decryptSubject(Subject subject) {
			if (subject != null) {
				if (subject.getEncryptedID() != null) {
					try {
						NameID decrypted = (NameID) this.decrypter.decrypt(subject.getEncryptedID());
						if (decrypted != null) {
							subject.setNameID(decrypted);
							subject.setEncryptedID(null);
						}
					}
					catch (final DecryptionException ex) {
						throw new Saml2Exception(ex);
					}
				}

				for (final SubjectConfirmation sc : subject.getSubjectConfirmations()) {
					if (sc.getEncryptedID() != null) {
						try {
							NameID decrypted = (NameID) this.decrypter.decrypt(sc.getEncryptedID());
							if (decrypted != null) {
								sc.setNameID(decrypted);
								sc.setEncryptedID(null);
							}
						}
						catch (final DecryptionException ex) {
							throw new Saml2Exception(ex);
						}
					}
				}
			}
		}

		private void decryptLogoutRequest(LogoutRequest request) {
			if (request.getEncryptedID() != null) {
				try {
					NameID decrypted = (NameID) this.decrypter.decrypt(request.getEncryptedID());
					if (decrypted != null) {
						request.setNameID(decrypted);
						request.setEncryptedID(null);
					}
				}
				catch (DecryptionException ex) {
					throw new Saml2Exception(ex);
				}
			}
		}

	}

}
