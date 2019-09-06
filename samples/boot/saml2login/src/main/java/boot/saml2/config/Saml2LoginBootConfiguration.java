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

package boot.saml2.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.registration.InMemoryRelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistrationRepository;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;
import org.springframework.util.StringUtils;

import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;

import static java.util.Collections.emptyList;
import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialType.DECRYPTION;
import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialType.ENCRYPTION;
import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialType.SIGNING;
import static org.springframework.security.saml2.credentials.Saml2X509Credential.Saml2X509CredentialType.VERIFICATION;

@Configuration
@ConfigurationProperties(prefix = "spring.security.saml2.login")
@Import(X509CredentialsConverters.class)
public class Saml2LoginBootConfiguration {

	private List<SampleRelyingParty> relyingParties;

	@Bean
	@ConditionalOnMissingBean
	public RelyingPartyRegistrationRepository relyingPartyRegistrationRepository() {
		return new InMemoryRelyingPartyRegistrationRepository(getRelyingParties(relyingParties));
	}

	public void setRelyingParties(List<SampleRelyingParty> providers) {
		this.relyingParties = providers;
	}

	private List<RelyingPartyRegistration> getRelyingParties(List<SampleRelyingParty> sampleRelyingParties) {
		String acsUrlTemplate = "{baseUrl}" + Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI;
		return sampleRelyingParties.stream()
				.map(
					p -> StringUtils.hasText(p.getLocalSpEntityIdTemplate()) ?
							RelyingPartyRegistration.withRegistrationId(p.getRegistrationId())
									.assertionConsumerServiceUrlTemplate(acsUrlTemplate)
									.remoteIdpEntityId(p.getEntityId())
									.idpWebSsoUrl(p.getWebSsoUrl())
									.credentials(c -> c.addAll(p.getProviderCredentials()))
									.localEntityIdTemplate(p.getLocalSpEntityIdTemplate())
									.build() :
							RelyingPartyRegistration.withRegistrationId(p.getRegistrationId())
									.assertionConsumerServiceUrlTemplate(acsUrlTemplate)
									.remoteIdpEntityId(p.getEntityId())
									.idpWebSsoUrl(p.getWebSsoUrl())
									.credentials(c -> c.addAll(p.getProviderCredentials()))
									.build()
				)
				.collect(Collectors.toList());
	}

	public static class SampleRelyingParty {

		private String entityId;
		private List<Saml2X509Credential> signingCredentials = emptyList();
		private List<X509Certificate> verificationCredentials = emptyList();
		private String registrationId;
		private String webSsoUrl;
		private String localSpEntityIdTemplate;

		public String getEntityId() {
			return entityId;
		}

		public String getLocalSpEntityIdTemplate() {
			return localSpEntityIdTemplate;
		}

		public void setEntityId(String entityId) {
			this.entityId = entityId;
		}

		public List<Saml2X509Credential> getSigningCredentials() {
			return signingCredentials;
		}

		public void setSigningCredentials(List<X509KeyCertificatePair> credentials) {
			this.signingCredentials = credentials
					.stream()
					.map(c ->
							new Saml2X509Credential(
									c.getPrivateKey(),
									c.getCertificate(),
									SIGNING,
									DECRYPTION
							)
					)
					.collect(Collectors.toList());
		}

		public void setVerificationCredentials(List<X509Certificate> credentials) {
			this.verificationCredentials = new LinkedList<>(credentials);
		}

		public List<X509Certificate> getVerificationCredentials() {
			return verificationCredentials;
		}

		public List<Saml2X509Credential> getProviderCredentials() {
			LinkedList<Saml2X509Credential> result = new LinkedList<>(getSigningCredentials());
			for (X509Certificate c : getVerificationCredentials()) {
				result.add(new Saml2X509Credential(c, ENCRYPTION, VERIFICATION));
			}
			return result;
		}

		public String getRegistrationId() {
			return registrationId;
		}

		public SampleRelyingParty setRegistrationId(String registrationId) {
			this.registrationId = registrationId;
			return this;
		}

		public String getWebSsoUrl() {
			return webSsoUrl;
		}

		public SampleRelyingParty setWebSsoUrl(String webSsoUrl) {
			this.webSsoUrl = webSsoUrl;
			return this;
		}

		public void setLocalSpEntityIdTemplate(String localSpEntityIdTemplate) {
			this.localSpEntityIdTemplate = localSpEntityIdTemplate;
		}
	}

	public static class X509KeyCertificatePair {

		private RSAPrivateKey privateKey;
		private X509Certificate certificate;

		public RSAPrivateKey getPrivateKey() {
			return this.privateKey;
		}

		public void setPrivateKey(RSAPrivateKey privateKey) {
			this.privateKey = privateKey;
		}

		public X509Certificate getCertificate() {
			return certificate;
		}

		public void setCertificate(X509Certificate certificate) {
			this.certificate = certificate;
		}

	}

}
