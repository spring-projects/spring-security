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

package org.springframework.security;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.NotSerializableException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.ObjectStreamClass;
import java.io.Serializable;
import java.lang.reflect.Modifier;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

import org.apereo.cas.client.validation.AssertionImpl;
import org.instancio.Instancio;
import org.instancio.InstancioApi;
import org.instancio.Select;
import org.instancio.generator.Generator;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.ClassPathScanningCandidateComponentProvider;
import org.springframework.core.type.filter.AssignableTypeFilter;
import org.springframework.security.access.intercept.RunAsUserToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.TestAuthentication;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.jaas.JaasAuthenticationToken;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationToken;
import org.springframework.security.cas.authentication.CasServiceTicketAuthenticationToken;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.session.ReactiveSessionInformation;
import org.springframework.security.core.session.SessionInformation;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationToken;
import org.springframework.security.oauth2.client.authentication.TestOAuth2AuthenticationTokens;
import org.springframework.security.oauth2.client.authentication.TestOAuth2AuthorizationCodeAuthenticationTokens;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2AuthenticatedPrincipals;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationExchange;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponse;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationExchanges;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationRequests;
import org.springframework.security.oauth2.core.endpoint.TestOAuth2AuthorizationResponses;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2UserAuthority;
import org.springframework.security.oauth2.core.user.TestOAuth2Users;
import org.springframework.security.oauth2.jwt.TestJwts;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.fail;

/**
 * Tests that Spring Security classes that implements {@link Serializable} and have the
 * same serial version as {@link SpringSecurityCoreVersion#SERIAL_VERSION_UID} can be
 * deserialized from a previous minor version.
 * <p>
 * For example, all classes from version 6.2.x that matches the previous requirement
 * should be serialized and saved to a folder, and then later on, in 6.3.x, it is verified
 * if they can be deserialized
 *
 * @author Marcus da Coregio
 * @since 6.2.2
 * @see <a href="https://github.com/spring-projects/spring-security/issues/3737">GitHub
 * Issue #3737</a>
 */
class SpringSecurityCoreVersionSerializableTests {

	private static final Map<Class<?>, Generator<?>> generatorByClassName = new HashMap<>();

	static final long securitySerialVersionUid = SpringSecurityCoreVersion.SERIAL_VERSION_UID;

	static Path currentVersionFolder = Paths.get("src/test/resources/serialized/" + getCurrentVersion());

	static Path previousVersionFolder = Paths.get("src/test/resources/serialized/" + getPreviousVersion());

	static {
		UserDetails user = TestAuthentication.user();

		// oauth2-core
		generatorByClassName.put(DefaultOAuth2User.class, (r) -> TestOAuth2Users.create());
		generatorByClassName.put(OAuth2AuthorizationRequest.class,
				(r) -> TestOAuth2AuthorizationRequests.request().build());
		generatorByClassName.put(OAuth2AuthorizationResponse.class,
				(r) -> TestOAuth2AuthorizationResponses.success().build());
		generatorByClassName.put(OAuth2UserAuthority.class, (r) -> new OAuth2UserAuthority(Map.of("username", "user")));
		generatorByClassName.put(OAuth2AuthorizationExchange.class, (r) -> TestOAuth2AuthorizationExchanges.success());
		generatorByClassName.put(OidcUserInfo.class, (r) -> OidcUserInfo.builder().email("email@example.com").build());
		generatorByClassName.put(SessionInformation.class,
				(r) -> new SessionInformation(user, r.alphanumeric(4), new Date(1704378933936L)));
		generatorByClassName.put(ReactiveSessionInformation.class,
				(r) -> new ReactiveSessionInformation(user, r.alphanumeric(4), Instant.ofEpochMilli(1704378933936L)));

		// oauth2-client
		ClientRegistration.Builder clientRegistrationBuilder = TestClientRegistrations.clientRegistration();
		ClientRegistration clientRegistration = clientRegistrationBuilder.build();
		WebAuthenticationDetails details = new WebAuthenticationDetails("remote", "sessionId");
		generatorByClassName.put(ClientRegistration.class, (r) -> clientRegistration);
		generatorByClassName.put(ClientRegistration.ProviderDetails.class,
				(r) -> clientRegistration.getProviderDetails());
		generatorByClassName.put(ClientRegistration.ProviderDetails.UserInfoEndpoint.class,
				(r) -> clientRegistration.getProviderDetails().getUserInfoEndpoint());
		generatorByClassName.put(ClientRegistration.Builder.class, (r) -> clientRegistrationBuilder);
		generatorByClassName.put(OAuth2AuthorizedClient.class,
				(r) -> new OAuth2AuthorizedClient(clientRegistration, "principal", TestOAuth2AccessTokens.noScopes()));
		generatorByClassName.put(OAuth2LoginAuthenticationToken.class, (r) -> {
			var token = new OAuth2LoginAuthenticationToken(clientRegistration,
					TestOAuth2AuthorizationExchanges.success());
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(OAuth2AuthorizationCodeAuthenticationToken.class, (r) -> {
			var token = TestOAuth2AuthorizationCodeAuthenticationTokens.authenticated();
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(OAuth2AuthenticationToken.class, (r) -> {
			var token = TestOAuth2AuthenticationTokens.authenticated();
			token.setDetails(details);
			return token;
		});

		// oauth2-resource-server
		generatorByClassName
			.put(org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken.class, (r) -> {
				var token = new org.springframework.security.oauth2.server.resource.BearerTokenAuthenticationToken(
						"token");
				token.setDetails(details);
				return token;
			});
		generatorByClassName.put(BearerTokenAuthenticationToken.class, (r) -> {
			var token = new BearerTokenAuthenticationToken("token");
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(BearerTokenAuthentication.class, (r) -> {
			var token = new BearerTokenAuthentication(TestOAuth2AuthenticatedPrincipals.active(),
					TestOAuth2AccessTokens.noScopes(), user.getAuthorities());
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(JwtAuthenticationToken.class, (r) -> {
			var token = new JwtAuthenticationToken(TestJwts.user());
			token.setDetails(details);
			return token;
		});

		// core
		generatorByClassName.put(RunAsUserToken.class, (r) -> {
			RunAsUserToken token = new RunAsUserToken("key", user, "creds", user.getAuthorities(),
					AnonymousAuthenticationToken.class);
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(RememberMeAuthenticationToken.class, (r) -> {
			RememberMeAuthenticationToken token = new RememberMeAuthenticationToken("key", user, user.getAuthorities());
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(UsernamePasswordAuthenticationToken.class, (r) -> {
			var token = UsernamePasswordAuthenticationToken.unauthenticated(user, "creds");
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(JaasAuthenticationToken.class, (r) -> {
			var token = new JaasAuthenticationToken(user, "creds", null);
			token.setDetails(details);
			return token;
		});

		// cas
		generatorByClassName.put(CasServiceTicketAuthenticationToken.class, (r) -> {
			CasServiceTicketAuthenticationToken token = CasServiceTicketAuthenticationToken.stateless("creds");
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(CasAuthenticationToken.class, (r) -> {
			var token = new CasAuthenticationToken("key", user, "Password", user.getAuthorities(), user,
					new AssertionImpl("test"));
			token.setDetails(details);
			return token;
		});
		generatorByClassName.put(CasAssertionAuthenticationToken.class, (r) -> {
			var token = new CasAssertionAuthenticationToken(new AssertionImpl("test"), "ticket");
			token.setDetails(details);
			return token;
		});

		// web
		generatorByClassName.put(PreAuthenticatedAuthenticationToken.class, (r) -> {
			PreAuthenticatedAuthenticationToken token = new PreAuthenticatedAuthenticationToken(user, "creds",
					user.getAuthorities());
			token.setDetails(details);
			return token;
		});
	}

	@ParameterizedTest
	@MethodSource("getClassesToSerialize")
	@Disabled("This method should only be used to serialize the classes once")
	void serializeCurrentVersionClasses(Class<?> clazz) throws Exception {
		Files.createDirectories(currentVersionFolder);
		Path filePath = Paths.get(currentVersionFolder.toAbsolutePath() + "/" + clazz.getName() + ".serialized");
		File file = filePath.toFile();
		if (file.exists()) {
			return;
		}
		Files.createFile(filePath);
		Object instance = instancioWithDefaults(clazz).create();
		assertThat(instance).isInstanceOf(clazz);
		try (FileOutputStream fileOutputStream = new FileOutputStream(file);
				ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream)) {
			objectOutputStream.writeObject(instance);
			objectOutputStream.flush();
		}
		catch (NotSerializableException ex) {
			Files.delete(filePath);
			fail("Could not serialize " + clazz.getName(), ex);
		}
	}

	@ParameterizedTest
	@MethodSource("getFilesToDeserialize")
	void shouldBeAbleToDeserializeClassFromPreviousVersion(Path filePath) {
		try (FileInputStream fileInputStream = new FileInputStream(filePath.toFile());
				ObjectInputStream objectInputStream = new ObjectInputStream(fileInputStream)) {
			Object obj = objectInputStream.readObject();
			Class<?> clazz = Class.forName(filePath.getFileName().toString().replace(".serialized", ""));
			assertThat(obj).isInstanceOf(clazz);
		}
		catch (IOException | ClassNotFoundException ex) {
			fail("Could not deserialize " + filePath, ex);
		}
	}

	static Stream<Path> getFilesToDeserialize() throws IOException {
		assertThat(previousVersionFolder.toFile().exists())
			.as("Make sure that the " + previousVersionFolder + " exists and is not empty")
			.isTrue();
		try (Stream<Path> files = Files.list(previousVersionFolder)) {
			if (files.findFirst().isEmpty()) {
				fail("Please make sure to run SpringSecurityCoreVersionSerializableTests#serializeCurrentVersionClasses for the "
						+ getPreviousVersion() + " version");
			}
		}
		return Files.list(previousVersionFolder);
	}

	static Stream<Class<?>> getClassesToSerialize() throws Exception {
		ClassPathScanningCandidateComponentProvider provider = new ClassPathScanningCandidateComponentProvider(false);
		provider.addIncludeFilter(new AssignableTypeFilter(Serializable.class));
		List<Class<?>> classes = new ArrayList<>();

		Set<BeanDefinition> components = provider.findCandidateComponents("org/springframework/security");
		for (BeanDefinition component : components) {
			Class<?> clazz = Class.forName(component.getBeanClassName());
			boolean isAbstract = Modifier.isAbstract(clazz.getModifiers());
			if (isAbstract) {
				continue;
			}
			boolean matchesExpectedSerialVersion = ObjectStreamClass.lookup(clazz)
				.getSerialVersionUID() == securitySerialVersionUid;
			boolean isUnderTest = generatorByClassName.containsKey(clazz);
			if (matchesExpectedSerialVersion || isUnderTest) {
				classes.add(clazz);
			}
		}
		return classes.stream();
	}

	private static InstancioApi<?> instancioWithDefaults(Class<?> clazz) {
		InstancioApi<?> instancio = Instancio.of(clazz);
		if (generatorByClassName.containsKey(clazz)) {
			instancio.supply(Select.all(clazz), generatorByClassName.get(clazz));
		}
		return instancio;
	}

	private static String getCurrentVersion() {
		String version = System.getProperty("springSecurityVersion");
		String[] parts = version.split("\\.");
		parts[2] = "x";
		return String.join(".", parts);
	}

	private static String getPreviousVersion() {
		String version = System.getProperty("springSecurityVersion");
		String[] parts = version.split("\\.");
		parts[1] = String.valueOf(Integer.parseInt(parts[1]) - 1);
		parts[2] = "x";
		return String.join(".", parts);
	}

}
