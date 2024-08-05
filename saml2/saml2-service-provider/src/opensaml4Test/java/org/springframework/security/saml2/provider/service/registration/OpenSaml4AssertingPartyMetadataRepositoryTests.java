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

package org.springframework.security.saml2.provider.service.registration;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.metadata.IterableMetadataSource;
import org.opensaml.saml.metadata.resolver.MetadataResolver;
import org.opensaml.saml.metadata.resolver.impl.FilesystemMetadataResolver;
import org.opensaml.saml.metadata.resolver.index.impl.RoleMetadataIndex;
import org.opensaml.saml.saml2.metadata.EntityDescriptor;
import org.opensaml.security.credential.Credential;
import org.w3c.dom.Element;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.core.TestSaml2X509Credentials;
import org.springframework.security.saml2.provider.service.authentication.TestOpenSamlObjects;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.withSettings;

/**
 * Tests for {@link BaseOpenSamlAssertingPartyMetadataRepository}
 */
public class OpenSaml4AssertingPartyMetadataRepositoryTests {

	static {
		OpenSamlInitializationService.initialize();
	}

	private String metadata;

	private String entitiesDescriptor;

	@BeforeEach
	public void setup() throws Exception {
		ClassPathResource resource = new ClassPathResource("test-metadata.xml");
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			this.metadata = reader.lines().collect(Collectors.joining());
		}
		resource = new ClassPathResource("test-entitiesdescriptor.xml");
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
			this.entitiesDescriptor = reader.lines().collect(Collectors.joining());
		}
	}

	@Test
	public void withMetadataUrlLocationWhenResolvableThenFindByEntityIdReturns() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(new AlwaysDispatch(new MockResponse().setBody(this.metadata).setResponseCode(200)));
			AssertingPartyMetadataRepository parties = OpenSaml4AssertingPartyMetadataRepository
				.withTrustedMetadataLocation(server.url("/").toString())
				.build();
			AssertingPartyMetadata party = parties.findByEntityId("https://idp.example.com/idp/shibboleth");
			assertThat(party.getEntityId()).isEqualTo("https://idp.example.com/idp/shibboleth");
			assertThat(party.getSingleSignOnServiceLocation())
				.isEqualTo("https://idp.example.com/idp/profile/SAML2/POST/SSO");
			assertThat(party.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
			assertThat(party.getVerificationX509Credentials()).hasSize(1);
			assertThat(party.getEncryptionX509Credentials()).hasSize(1);
		}
	}

	@Test
	public void withMetadataUrlLocationnWhenResolvableThenIteratorReturns() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(
					new AlwaysDispatch(new MockResponse().setBody(this.entitiesDescriptor).setResponseCode(200)));
			List<AssertingPartyMetadata> parties = new ArrayList<>();
			OpenSaml4AssertingPartyMetadataRepository.withTrustedMetadataLocation(server.url("/").toString())
				.build()
				.iterator()
				.forEachRemaining(parties::add);
			assertThat(parties).hasSize(2);
			assertThat(parties).extracting(AssertingPartyMetadata::getEntityId)
				.contains("https://ap.example.org/idp/shibboleth", "https://idp.example.com/idp/shibboleth");
		}
	}

	@Test
	public void withMetadataUrlLocationWhenUnresolvableThenThrowsSaml2Exception() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.enqueue(new MockResponse().setBody(this.metadata).setResponseCode(200));
			String url = server.url("/").toString();
			server.shutdown();
			assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> OpenSaml4AssertingPartyMetadataRepository.withTrustedMetadataLocation(url).build());
		}
	}

	@Test
	public void withMetadataUrlLocationWhenMalformedResponseThenSaml2Exception() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			server.setDispatcher(new AlwaysDispatch("malformed"));
			String url = server.url("/").toString();
			assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> OpenSaml4AssertingPartyMetadataRepository.withTrustedMetadataLocation(url).build());
		}
	}

	@Test
	public void fromMetadataFileLocationWhenResolvableThenFindByEntityIdReturns() {
		File file = new File("src/test/resources/test-metadata.xml");
		AssertingPartyMetadata party = OpenSaml4AssertingPartyMetadataRepository
			.withTrustedMetadataLocation("file:" + file.getAbsolutePath())
			.build()
			.findByEntityId("https://idp.example.com/idp/shibboleth");
		assertThat(party.getEntityId()).isEqualTo("https://idp.example.com/idp/shibboleth");
		assertThat(party.getSingleSignOnServiceLocation())
			.isEqualTo("https://idp.example.com/idp/profile/SAML2/POST/SSO");
		assertThat(party.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(party.getVerificationX509Credentials()).hasSize(1);
		assertThat(party.getEncryptionX509Credentials()).hasSize(1);
	}

	@Test
	public void fromMetadataFileLocationWhenResolvableThenIteratorReturns() {
		File file = new File("src/test/resources/test-entitiesdescriptor.xml");
		Collection<AssertingPartyMetadata> parties = new ArrayList<>();
		OpenSaml4AssertingPartyMetadataRepository.withTrustedMetadataLocation("file:" + file.getAbsolutePath())
			.build()
			.iterator()
			.forEachRemaining(parties::add);
		assertThat(parties).hasSize(2);
		assertThat(parties).extracting(AssertingPartyMetadata::getEntityId)
			.contains("https://idp.example.com/idp/shibboleth", "https://ap.example.org/idp/shibboleth");
	}

	@Test
	public void withMetadataFileLocationWhenNotFoundThenSaml2Exception() {
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(
				() -> OpenSaml4AssertingPartyMetadataRepository.withTrustedMetadataLocation("file:path").build());
	}

	@Test
	public void fromMetadataClasspathLocationWhenResolvableThenFindByEntityIdReturns() {
		AssertingPartyMetadata party = OpenSaml4AssertingPartyMetadataRepository
			.withTrustedMetadataLocation("classpath:test-entitiesdescriptor.xml")
			.build()
			.findByEntityId("https://ap.example.org/idp/shibboleth");
		assertThat(party.getEntityId()).isEqualTo("https://ap.example.org/idp/shibboleth");
		assertThat(party.getSingleSignOnServiceLocation())
			.isEqualTo("https://ap.example.org/idp/profile/SAML2/POST/SSO");
		assertThat(party.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(party.getVerificationX509Credentials()).hasSize(1);
		assertThat(party.getEncryptionX509Credentials()).hasSize(1);
	}

	@Test
	public void fromMetadataClasspathLocationWhenResolvableThenIteratorReturns() {
		Collection<AssertingPartyMetadata> parties = new ArrayList<>();
		OpenSaml4AssertingPartyMetadataRepository.withTrustedMetadataLocation("classpath:test-entitiesdescriptor.xml")
			.build()
			.iterator()
			.forEachRemaining(parties::add);
		assertThat(parties).hasSize(2);
		assertThat(parties).extracting(AssertingPartyMetadata::getEntityId)
			.contains("https://idp.example.com/idp/shibboleth", "https://ap.example.org/idp/shibboleth");
	}

	@Test
	public void withMetadataClasspathLocationWhenNotFoundThenSaml2Exception() {
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(
				() -> OpenSaml4AssertingPartyMetadataRepository.withTrustedMetadataLocation("classpath:path").build());
	}

	@Test
	public void withTrustedMetadataLocationWhenMatchingCredentialsThenVerifiesSignature() throws IOException {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		EntityDescriptor descriptor = TestOpenSamlObjects.entityDescriptor(registration);
		TestOpenSamlObjects.signed(descriptor, TestSaml2X509Credentials.assertingPartySigningCredential(),
				descriptor.getEntityID());
		String serialized = serialize(descriptor);
		Credential credential = TestOpenSamlObjects
			.getSigningCredential(TestSaml2X509Credentials.relyingPartyVerifyingCredential(), descriptor.getEntityID());
		try (MockWebServer server = new MockWebServer()) {
			server.start();
			server.setDispatcher(new AlwaysDispatch(serialized));
			AssertingPartyMetadataRepository parties = OpenSaml4AssertingPartyMetadataRepository
				.withTrustedMetadataLocation(server.url("/").toString())
				.verificationCredentials((c) -> c.add(credential))
				.build();
			assertThat(parties.findByEntityId(registration.getAssertingPartyDetails().getEntityId())).isNotNull();
		}
	}

	@Test
	public void withTrustedMetadataLocationWhenMismatchingCredentialsThenSaml2Exception() throws IOException {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		EntityDescriptor descriptor = TestOpenSamlObjects.entityDescriptor(registration);
		TestOpenSamlObjects.signed(descriptor, TestSaml2X509Credentials.relyingPartySigningCredential(),
				descriptor.getEntityID());
		String serialized = serialize(descriptor);
		Credential credential = TestOpenSamlObjects
			.getSigningCredential(TestSaml2X509Credentials.relyingPartyVerifyingCredential(), descriptor.getEntityID());
		try (MockWebServer server = new MockWebServer()) {
			server.start();
			server.setDispatcher(new AlwaysDispatch(serialized));
			assertThatExceptionOfType(Saml2Exception.class).isThrownBy(() -> OpenSaml4AssertingPartyMetadataRepository
				.withTrustedMetadataLocation(server.url("/").toString())
				.verificationCredentials((c) -> c.add(credential))
				.build());
		}
	}

	@Test
	public void withTrustedMetadataLocationWhenNoCredentialsThenSkipsVerifySignature() throws IOException {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		EntityDescriptor descriptor = TestOpenSamlObjects.entityDescriptor(registration);
		TestOpenSamlObjects.signed(descriptor, TestSaml2X509Credentials.assertingPartySigningCredential(),
				descriptor.getEntityID());
		String serialized = serialize(descriptor);
		try (MockWebServer server = new MockWebServer()) {
			server.start();
			server.setDispatcher(new AlwaysDispatch(serialized));
			AssertingPartyMetadataRepository parties = OpenSaml4AssertingPartyMetadataRepository
				.withTrustedMetadataLocation(server.url("/").toString())
				.build();
			assertThat(parties.findByEntityId(registration.getAssertingPartyDetails().getEntityId())).isNotNull();
		}
	}

	@Test
	public void withTrustedMetadataLocationWhenCustomResourceLoaderThenUses() {
		ResourceLoader resourceLoader = mock(ResourceLoader.class);
		given(resourceLoader.getResource(any())).willReturn(new ClassPathResource("test-metadata.xml"));
		AssertingPartyMetadata party = OpenSaml4AssertingPartyMetadataRepository
			.withTrustedMetadataLocation("classpath:wrong")
			.resourceLoader(resourceLoader)
			.build()
			.iterator()
			.next();
		assertThat(party.getEntityId()).isEqualTo("https://idp.example.com/idp/shibboleth");
		assertThat(party.getSingleSignOnServiceLocation())
			.isEqualTo("https://idp.example.com/idp/profile/SAML2/POST/SSO");
		assertThat(party.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(party.getVerificationX509Credentials()).hasSize(1);
		assertThat(party.getEncryptionX509Credentials()).hasSize(1);
		verify(resourceLoader).getResource(any());
	}

	@Test
	public void constructorWhenNoIndexAndNoIteratorThenException() {
		MetadataResolver resolver = mock(MetadataResolver.class);
		assertThatExceptionOfType(IllegalArgumentException.class)
			.isThrownBy(() -> new OpenSaml4AssertingPartyMetadataRepository(resolver));
	}

	@Test
	public void constructorWhenIterableResolverThenUses() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		EntityDescriptor descriptor = TestOpenSamlObjects.entityDescriptor(registration);
		MetadataResolver resolver = mock(MetadataResolver.class,
				withSettings().extraInterfaces(IterableMetadataSource.class));
		given(((IterableMetadataSource) resolver).iterator()).willReturn(List.of(descriptor).iterator());
		AssertingPartyMetadataRepository parties = new OpenSaml4AssertingPartyMetadataRepository(resolver);
		parties.iterator()
			.forEachRemaining((p) -> assertThat(p.getEntityId())
				.isEqualTo(registration.getAssertingPartyDetails().getEntityId()));
		verify(((IterableMetadataSource) resolver)).iterator();
	}

	@Test
	public void constructorWhenIndexedResolverThenUses() throws Exception {
		FilesystemMetadataResolver resolver = new FilesystemMetadataResolver(
				new ClassPathResource("test-metadata.xml").getFile());
		resolver.setIndexes(Set.of(new RoleMetadataIndex()));
		resolver.setId("id");
		resolver.setParserPool(XMLObjectProviderRegistrySupport.getParserPool());
		resolver.initialize();
		MetadataResolver spied = spy(resolver);
		AssertingPartyMetadataRepository parties = new OpenSaml4AssertingPartyMetadataRepository(spied);
		parties.iterator()
			.forEachRemaining((p) -> assertThat(p.getEntityId()).isEqualTo("https://idp.example.com/idp/shibboleth"));
		verify(spied).resolve(any());
	}

	@Test
	public void withMetadataLocationWhenNoCredentialsThenException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> OpenSaml4AssertingPartyMetadataRepository.withMetadataLocation("classpath:test-metadata.xml")
					.build());
	}

	@Test
	public void withMetadataLocationWhenMatchingCredentialsThenVerifiesSignature() throws IOException {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		EntityDescriptor descriptor = TestOpenSamlObjects.entityDescriptor(registration);
		TestOpenSamlObjects.signed(descriptor, TestSaml2X509Credentials.assertingPartySigningCredential(),
				descriptor.getEntityID());
		String serialized = serialize(descriptor);
		Credential credential = TestOpenSamlObjects
			.getSigningCredential(TestSaml2X509Credentials.relyingPartyVerifyingCredential(), descriptor.getEntityID());
		try (MockWebServer server = new MockWebServer()) {
			server.start();
			server.setDispatcher(new AlwaysDispatch(serialized));
			AssertingPartyMetadataRepository parties = OpenSaml4AssertingPartyMetadataRepository
				.withMetadataLocation(server.url("/").toString())
				.verificationCredentials((c) -> c.add(credential))
				.build();
			assertThat(parties.findByEntityId(registration.getAssertingPartyDetails().getEntityId())).isNotNull();
		}
	}

	private static String serialize(XMLObject object) {
		try {
			Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
			Element element = marshaller.marshall(object);
			return SerializeSupport.nodeToString(element);
		}
		catch (MarshallingException ex) {
			throw new Saml2Exception(ex);
		}
	}

	private static final class AlwaysDispatch extends Dispatcher {

		private final MockResponse response;

		private AlwaysDispatch(String body) {
			this.response = new MockResponse().setBody(body).setResponseCode(200);
		}

		private AlwaysDispatch(MockResponse response) {
			this.response = response;
		}

		@Override
		public MockResponse dispatch(RecordedRequest recordedRequest) throws InterruptedException {
			return this.response;
		}

	}

}
