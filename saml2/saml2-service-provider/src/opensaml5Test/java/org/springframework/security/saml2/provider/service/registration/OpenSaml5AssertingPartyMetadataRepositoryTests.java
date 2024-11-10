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
import java.io.UncheckedIOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.stream.Collectors;

import net.shibboleth.shared.xml.SerializeSupport;
import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
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
public class OpenSaml5AssertingPartyMetadataRepositoryTests {

	private static MetadataDispatcher dispatcher = new MetadataDispatcher()
		.addResponse("/entity.xml", readFile("test-metadata.xml"))
		.addResponse("/entities.xml", readFile("test-entitiesdescriptor.xml"));

	private static MockWebServer web = new MockWebServer();

	private static String readFile(String fileName) {
		try {
			ClassPathResource resource = new ClassPathResource(fileName);
			try (BufferedReader reader = new BufferedReader(new InputStreamReader(resource.getInputStream()))) {
				return reader.lines().collect(Collectors.joining());
			}
		}
		catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}

	@BeforeAll
	public static void start() throws Exception {
		web.setDispatcher(dispatcher);
		web.start();
	}

	@AfterAll
	public static void shutdown() throws Exception {
		web.shutdown();
	}

	@Test
	public void withMetadataUrlLocationWhenResolvableThenFindByEntityIdReturns() throws Exception {
		AssertingPartyMetadataRepository parties = OpenSaml5AssertingPartyMetadataRepository
			.withTrustedMetadataLocation(web.url("/entity.xml").toString())
			.build();
		AssertingPartyMetadata party = parties.findByEntityId("https://idp.example.com/idp/shibboleth");
		assertThat(party.getEntityId()).isEqualTo("https://idp.example.com/idp/shibboleth");
		assertThat(party.getSingleSignOnServiceLocation())
			.isEqualTo("https://idp.example.com/idp/profile/SAML2/POST/SSO");
		assertThat(party.getSingleSignOnServiceBinding()).isEqualTo(Saml2MessageBinding.POST);
		assertThat(party.getVerificationX509Credentials()).hasSize(1);
		assertThat(party.getEncryptionX509Credentials()).hasSize(1);
	}

	@Test
	public void withMetadataUrlLocationnWhenResolvableThenIteratorReturns() throws Exception {
		List<AssertingPartyMetadata> parties = new ArrayList<>();
		OpenSaml5AssertingPartyMetadataRepository.withTrustedMetadataLocation(web.url("/entities.xml").toString())
			.build()
			.iterator()
			.forEachRemaining(parties::add);
		assertThat(parties).hasSize(2);
		assertThat(parties).extracting(AssertingPartyMetadata::getEntityId)
			.contains("https://ap.example.org/idp/shibboleth", "https://idp.example.com/idp/shibboleth");
	}

	@Test
	public void withMetadataUrlLocationWhenUnresolvableThenThrowsSaml2Exception() throws Exception {
		try (MockWebServer server = new MockWebServer()) {
			String url = server.url("/").toString();
			server.shutdown();
			assertThatExceptionOfType(Saml2Exception.class)
				.isThrownBy(() -> OpenSaml5AssertingPartyMetadataRepository.withTrustedMetadataLocation(url).build());
		}
	}

	@Test
	public void withMetadataUrlLocationWhenMalformedResponseThenSaml2Exception() throws Exception {
		dispatcher.addResponse("/malformed", "malformed");
		String url = web.url("/malformed").toString();
		assertThatExceptionOfType(Saml2Exception.class)
			.isThrownBy(() -> OpenSaml5AssertingPartyMetadataRepository.withTrustedMetadataLocation(url).build());
	}

	@Test
	public void fromMetadataFileLocationWhenResolvableThenFindByEntityIdReturns() {
		File file = new File("src/test/resources/test-metadata.xml");
		AssertingPartyMetadata party = OpenSaml5AssertingPartyMetadataRepository
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
		OpenSaml5AssertingPartyMetadataRepository.withTrustedMetadataLocation("file:" + file.getAbsolutePath())
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
				() -> OpenSaml5AssertingPartyMetadataRepository.withTrustedMetadataLocation("file:path").build());
	}

	@Test
	public void fromMetadataClasspathLocationWhenResolvableThenFindByEntityIdReturns() {
		AssertingPartyMetadata party = OpenSaml5AssertingPartyMetadataRepository
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
		OpenSaml5AssertingPartyMetadataRepository.withTrustedMetadataLocation("classpath:test-entitiesdescriptor.xml")
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
				() -> OpenSaml5AssertingPartyMetadataRepository.withTrustedMetadataLocation("classpath:path").build());
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
		String endpoint = "/" + UUID.randomUUID().toString();
		dispatcher.addResponse(endpoint, serialized);
		AssertingPartyMetadataRepository parties = OpenSaml5AssertingPartyMetadataRepository
			.withTrustedMetadataLocation(web.url(endpoint).toString())
			.verificationCredentials((c) -> c.add(credential))
			.build();
		assertThat(parties.findByEntityId(registration.getAssertingPartyDetails().getEntityId())).isNotNull();
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
		String endpoint = "/" + UUID.randomUUID().toString();
		dispatcher.addResponse(endpoint, serialized);
		assertThatExceptionOfType(Saml2Exception.class).isThrownBy(() -> OpenSaml5AssertingPartyMetadataRepository
			.withTrustedMetadataLocation(web.url(endpoint).toString())
			.verificationCredentials((c) -> c.add(credential))
			.build());
	}

	@Test
	public void withTrustedMetadataLocationWhenNoCredentialsThenSkipsVerifySignature() throws IOException {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		EntityDescriptor descriptor = TestOpenSamlObjects.entityDescriptor(registration);
		TestOpenSamlObjects.signed(descriptor, TestSaml2X509Credentials.assertingPartySigningCredential(),
				descriptor.getEntityID());
		String serialized = serialize(descriptor);
		String endpoint = "/" + UUID.randomUUID().toString();
		dispatcher.addResponse(endpoint, serialized);
		AssertingPartyMetadataRepository parties = OpenSaml5AssertingPartyMetadataRepository
			.withTrustedMetadataLocation(web.url(endpoint).toString())
			.build();
		assertThat(parties.findByEntityId(registration.getAssertingPartyDetails().getEntityId())).isNotNull();
	}

	@Test
	public void withTrustedMetadataLocationWhenCustomResourceLoaderThenUses() {
		ResourceLoader resourceLoader = mock(ResourceLoader.class);
		given(resourceLoader.getResource(any())).willReturn(new ClassPathResource("test-metadata.xml"));
		AssertingPartyMetadata party = OpenSaml5AssertingPartyMetadataRepository
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
			.isThrownBy(() -> new OpenSaml5AssertingPartyMetadataRepository(resolver));
	}

	@Test
	public void constructorWhenIterableResolverThenUses() {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		EntityDescriptor descriptor = TestOpenSamlObjects.entityDescriptor(registration);
		MetadataResolver resolver = mock(MetadataResolver.class,
				withSettings().extraInterfaces(IterableMetadataSource.class));
		given(((IterableMetadataSource) resolver).iterator()).willReturn(List.of(descriptor).iterator());
		AssertingPartyMetadataRepository parties = new OpenSaml5AssertingPartyMetadataRepository(resolver);
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
		AssertingPartyMetadataRepository parties = new OpenSaml5AssertingPartyMetadataRepository(spied);
		parties.iterator()
			.forEachRemaining((p) -> assertThat(p.getEntityId()).isEqualTo("https://idp.example.com/idp/shibboleth"));
		verify(spied).resolve(any());
	}

	@Test
	public void withMetadataLocationWhenNoCredentialsThenException() {
		assertThatExceptionOfType(IllegalArgumentException.class).isThrownBy(
				() -> OpenSaml5AssertingPartyMetadataRepository.withMetadataLocation("classpath:test-metadata.xml")
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
		String endpoint = "/" + UUID.randomUUID().toString();
		dispatcher.addResponse(endpoint, serialized);
		AssertingPartyMetadataRepository parties = OpenSaml5AssertingPartyMetadataRepository
			.withMetadataLocation(web.url(endpoint).toString())
			.verificationCredentials((c) -> c.add(credential))
			.build();
		assertThat(parties.findByEntityId(registration.getAssertingPartyDetails().getEntityId())).isNotNull();
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

	private static final class MetadataDispatcher extends Dispatcher {

		private final MockResponse head = new MockResponse();

		private final Map<String, MockResponse> responses = new ConcurrentHashMap<>();

		private MetadataDispatcher() {
		}

		@Override
		public MockResponse dispatch(RecordedRequest request) throws InterruptedException {
			if ("HEAD".equals(request.getMethod())) {
				return this.head;
			}
			return this.responses.get(request.getPath());
		}

		private MetadataDispatcher addResponse(String path, String body) {
			this.responses.put(path, new MockResponse().setBody(body).setResponseCode(200));
			return this;
		}

	}

}
