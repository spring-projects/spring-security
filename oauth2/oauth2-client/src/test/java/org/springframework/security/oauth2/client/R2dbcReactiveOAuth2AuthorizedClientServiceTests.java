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

package org.springframework.security.oauth2.client;

import io.r2dbc.h2.H2ConnectionFactory;
import io.r2dbc.spi.ConnectionFactory;
import io.r2dbc.spi.Result;
import org.junit.Before;
import org.junit.Test;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import org.springframework.core.io.ClassPathResource;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.r2dbc.connection.init.CompositeDatabasePopulator;
import org.springframework.r2dbc.connection.init.ConnectionFactoryInitializer;
import org.springframework.r2dbc.connection.init.ResourceDatabasePopulator;
import org.springframework.r2dbc.core.DatabaseClient;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.TestClientRegistrations;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.TestOAuth2AccessTokens;
import org.springframework.security.oauth2.core.TestOAuth2RefreshTokens;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatExceptionOfType;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link R2dbcReactiveOAuth2AuthorizedClientService}
 *
 * @author Ovidiu Popa
 *
 */
public class R2dbcReactiveOAuth2AuthorizedClientServiceTests {

	private static final String OAUTH2_CLIENT_SCHEMA_SQL_RESOURCE = "org/springframework/security/oauth2/client/oauth2-client-schema.sql";

	private ClientRegistration clientRegistration;

	private ReactiveClientRegistrationRepository clientRegistrationRepository;

	private DatabaseClient databaseClient;

	private static int principalId = 1000;

	private R2dbcReactiveOAuth2AuthorizedClientService authorizedClientService;

	@Before
	public void setUp() {
		final ConnectionFactory connectionFactory = createDb();
		this.clientRegistration = TestClientRegistrations.clientRegistration().build();
		this.clientRegistrationRepository = mock(ReactiveClientRegistrationRepository.class);
		given(this.clientRegistrationRepository.findByRegistrationId(anyString()))
				.willReturn(Mono.just(this.clientRegistration));
		this.databaseClient = DatabaseClient.create(connectionFactory);
		this.authorizedClientService = new R2dbcReactiveOAuth2AuthorizedClientService(this.databaseClient,
				this.clientRegistrationRepository);
	}

	@Test
	public void constructorWhenDatabaseClientIsNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(
						() -> new R2dbcReactiveOAuth2AuthorizedClientService(null, this.clientRegistrationRepository))
				.withMessageContaining("databaseClient cannot be null");
	}

	@Test
	public void constructorWhenClientRegistrationRepositoryIsNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> new R2dbcReactiveOAuth2AuthorizedClientService(mock(DatabaseClient.class), null))
				.withMessageContaining("clientRegistrationRepository cannot be null");
	}

	@Test
	public void loadAuthorizedClientWhenClientRegistrationIdIsNullThenThrowIllegalArgumentException() {

		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.authorizedClientService.loadAuthorizedClient(null, "principalName"))
				.withMessageContaining("clientRegistrationId cannot be empty");

	}

	@Test
	public void loadAuthorizedClientWhenPrincipalNameIsNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.authorizedClientService
						.loadAuthorizedClient(this.clientRegistration.getRegistrationId(), null))
				.withMessageContaining("principalName cannot be empty");
	}

	@Test
	public void loadAuthorizedClientWhenDoesNotExistThenReturnNull() {
		this.authorizedClientService.loadAuthorizedClient("registration-not-found", "principalName")
				.as(StepVerifier::create).expectNextCount(0).verifyComplete();
	}

	@Test
	public void loadAuthorizedClientWhenExistsThenReturnAuthorizedClient() {
		Authentication principal = createPrincipal();
		OAuth2AuthorizedClient expected = createAuthorizedClient(principal, this.clientRegistration);
		this.authorizedClientService.saveAuthorizedClient(expected, principal).as(StepVerifier::create)
				.verifyComplete();

		this.authorizedClientService
				.loadAuthorizedClient(this.clientRegistration.getRegistrationId(), principal.getName())
				.as(StepVerifier::create).assertNext((authorizedClient) -> {
					assertThat(authorizedClient).isNotNull();
					assertThat(authorizedClient.getClientRegistration()).isEqualTo(expected.getClientRegistration());
					assertThat(authorizedClient.getPrincipalName()).isEqualTo(expected.getPrincipalName());
					assertThat(authorizedClient.getAccessToken().getTokenType())
							.isEqualTo(expected.getAccessToken().getTokenType());
					assertThat(authorizedClient.getAccessToken().getTokenValue())
							.isEqualTo(expected.getAccessToken().getTokenValue());
					assertThat(authorizedClient.getAccessToken().getIssuedAt())
							.isEqualTo(expected.getAccessToken().getIssuedAt());
					assertThat(authorizedClient.getAccessToken().getExpiresAt())
							.isEqualTo(expected.getAccessToken().getExpiresAt());
					assertThat(authorizedClient.getAccessToken().getScopes())
							.isEqualTo(expected.getAccessToken().getScopes());
					assertThat(authorizedClient.getRefreshToken().getTokenValue())
							.isEqualTo(expected.getRefreshToken().getTokenValue());
					assertThat(authorizedClient.getRefreshToken().getIssuedAt())
							.isEqualTo(expected.getRefreshToken().getIssuedAt());
				}).verifyComplete();

	}

	@Test
	public void loadAuthorizedClientWhenExistsButNotFoundInClientRegistrationRepositoryThenThrowDataRetrievalFailureException() {
		given(this.clientRegistrationRepository.findByRegistrationId(any())).willReturn(Mono.empty());
		Authentication principal = createPrincipal();
		OAuth2AuthorizedClient expected = createAuthorizedClient(principal, this.clientRegistration);

		this.authorizedClientService.saveAuthorizedClient(expected, principal).as(StepVerifier::create)
				.verifyComplete();

		this.authorizedClientService
				.loadAuthorizedClient(this.clientRegistration.getRegistrationId(), principal.getName())
				.as(StepVerifier::create)
				.verifyErrorSatisfies((exception) -> assertThat(exception)
						.isInstanceOf(DataRetrievalFailureException.class)
						.hasMessage("The ClientRegistration with id '" + this.clientRegistration.getRegistrationId()
								+ "' exists in the data source, however, it was not found in the ClientRegistrationRepository."));
	}

	@Test
	public void saveAuthorizedClientWhenAuthorizedClientIsNullThenThrowIllegalArgumentException() {
		Authentication principal = createPrincipal();

		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.authorizedClientService.saveAuthorizedClient(null, principal))
				.withMessageContaining("authorizedClient cannot be null");

	}

	@Test
	public void saveAuthorizedClientWhenPrincipalIsNullThenThrowIllegalArgumentException() {
		Authentication principal = createPrincipal();
		OAuth2AuthorizedClient authorizedClient = createAuthorizedClient(principal, this.clientRegistration);
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.authorizedClientService.saveAuthorizedClient(authorizedClient, null))
				.withMessageContaining("principal cannot be null");
	}

	@Test
	public void saveAuthorizedClientWhenSaveThenLoadReturnsSaved() {
		Authentication principal = createPrincipal();
		final OAuth2AuthorizedClient expected = createAuthorizedClient(principal, this.clientRegistration);

		this.authorizedClientService.saveAuthorizedClient(expected, principal).as(StepVerifier::create)
				.verifyComplete();

		this.authorizedClientService
				.loadAuthorizedClient(this.clientRegistration.getRegistrationId(), principal.getName())
				.as(StepVerifier::create).assertNext((authorizedClient) -> {
					assertThat(authorizedClient).isNotNull();
					assertThat(authorizedClient.getClientRegistration()).isEqualTo(expected.getClientRegistration());
					assertThat(authorizedClient.getPrincipalName()).isEqualTo(expected.getPrincipalName());
					assertThat(authorizedClient.getAccessToken().getTokenType())
							.isEqualTo(expected.getAccessToken().getTokenType());
					assertThat(authorizedClient.getAccessToken().getTokenValue())
							.isEqualTo(expected.getAccessToken().getTokenValue());
					assertThat(authorizedClient.getAccessToken().getIssuedAt())
							.isEqualTo(expected.getAccessToken().getIssuedAt());
					assertThat(authorizedClient.getAccessToken().getExpiresAt())
							.isEqualTo(expected.getAccessToken().getExpiresAt());
					assertThat(authorizedClient.getAccessToken().getScopes())
							.isEqualTo(expected.getAccessToken().getScopes());
					assertThat(authorizedClient.getRefreshToken().getTokenValue())
							.isEqualTo(expected.getRefreshToken().getTokenValue());
					assertThat(authorizedClient.getRefreshToken().getIssuedAt())
							.isEqualTo(expected.getRefreshToken().getIssuedAt());
				}).verifyComplete();

		// Test save/load of NOT NULL attributes only
		principal = createPrincipal();
		OAuth2AuthorizedClient updatedExpectedPrincipal = createAuthorizedClient(principal, this.clientRegistration,
				true);
		this.authorizedClientService.saveAuthorizedClient(updatedExpectedPrincipal, principal).as(StepVerifier::create)
				.verifyComplete();

		this.authorizedClientService
				.loadAuthorizedClient(this.clientRegistration.getRegistrationId(), principal.getName())
				.as(StepVerifier::create).assertNext((authorizedClient) -> {
					assertThat(authorizedClient).isNotNull();
					assertThat(authorizedClient.getClientRegistration())
							.isEqualTo(updatedExpectedPrincipal.getClientRegistration());
					assertThat(authorizedClient.getPrincipalName())
							.isEqualTo(updatedExpectedPrincipal.getPrincipalName());
					assertThat(authorizedClient.getAccessToken().getTokenType())
							.isEqualTo(updatedExpectedPrincipal.getAccessToken().getTokenType());
					assertThat(authorizedClient.getAccessToken().getTokenValue())
							.isEqualTo(updatedExpectedPrincipal.getAccessToken().getTokenValue());
					assertThat(authorizedClient.getAccessToken().getIssuedAt())
							.isEqualTo(updatedExpectedPrincipal.getAccessToken().getIssuedAt());
					assertThat(authorizedClient.getAccessToken().getExpiresAt())
							.isEqualTo(updatedExpectedPrincipal.getAccessToken().getExpiresAt());
					assertThat(authorizedClient.getAccessToken().getScopes()).isEmpty();
					assertThat(authorizedClient.getRefreshToken()).isNull();
				}).verifyComplete();
	}

	@Test
	public void saveAuthorizedClientWhenSaveClientWithExistingPrimaryKeyThenUpdate() {
		// Given a saved authorized client
		Authentication principal = createPrincipal();
		OAuth2AuthorizedClient authorizedClient = createAuthorizedClient(principal, this.clientRegistration);
		this.authorizedClientService.saveAuthorizedClient(authorizedClient, principal).as(StepVerifier::create)
				.verifyComplete();

		// When a client with the same principal and registration id is saved
		OAuth2AuthorizedClient updatedClient = createAuthorizedClient(principal, this.clientRegistration);
		this.authorizedClientService.saveAuthorizedClient(updatedClient, principal).as(StepVerifier::create)
				.verifyComplete();

		// Then the saved client is updated
		this.authorizedClientService
				.loadAuthorizedClient(this.clientRegistration.getRegistrationId(), principal.getName())
				.as(StepVerifier::create).assertNext((savedClient) -> {
					assertThat(savedClient).isNotNull();
					assertThat(savedClient.getClientRegistration()).isEqualTo(updatedClient.getClientRegistration());
					assertThat(savedClient.getPrincipalName()).isEqualTo(updatedClient.getPrincipalName());
					assertThat(savedClient.getAccessToken().getTokenType())
							.isEqualTo(updatedClient.getAccessToken().getTokenType());
					assertThat(savedClient.getAccessToken().getTokenValue())
							.isEqualTo(updatedClient.getAccessToken().getTokenValue());
					assertThat(savedClient.getAccessToken().getIssuedAt())
							.isEqualTo(updatedClient.getAccessToken().getIssuedAt());
					assertThat(savedClient.getAccessToken().getExpiresAt())
							.isEqualTo(updatedClient.getAccessToken().getExpiresAt());
					assertThat(savedClient.getAccessToken().getScopes())
							.isEqualTo(updatedClient.getAccessToken().getScopes());
					assertThat(savedClient.getRefreshToken().getTokenValue())
							.isEqualTo(updatedClient.getRefreshToken().getTokenValue());
					assertThat(savedClient.getRefreshToken().getIssuedAt())
							.isEqualTo(updatedClient.getRefreshToken().getIssuedAt());
				});
	}

	@Test
	public void removeAuthorizedClientWhenClientRegistrationIdIsNullThenThrowIllegalArgumentException() {

		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.authorizedClientService.removeAuthorizedClient(null, "principalName"))
				.withMessageContaining("clientRegistrationId cannot be empty");
	}

	@Test
	public void removeAuthorizedClientWhenPrincipalNameIsNullThenThrowIllegalArgumentException() {
		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.authorizedClientService
						.removeAuthorizedClient(this.clientRegistration.getRegistrationId(), null))
				.withMessageContaining("principalName cannot be empty");
	}

	@Test
	public void removeAuthorizedClientWhenExistsThenRemoved() {
		Authentication principal = createPrincipal();
		OAuth2AuthorizedClient authorizedClient = createAuthorizedClient(principal, this.clientRegistration);

		this.authorizedClientService.saveAuthorizedClient(authorizedClient, principal).as(StepVerifier::create)
				.verifyComplete();

		this.authorizedClientService
				.loadAuthorizedClient(this.clientRegistration.getRegistrationId(), principal.getName())
				.as(StepVerifier::create).assertNext((dbAuthorizedClient) -> assertThat(dbAuthorizedClient).isNotNull())
				.verifyComplete();

		this.authorizedClientService
				.removeAuthorizedClient(this.clientRegistration.getRegistrationId(), principal.getName())
				.as(StepVerifier::create).verifyComplete();

		Mono<OAuth2AuthorizedClient> loadMono = this.authorizedClientService
				.loadAuthorizedClient(this.clientRegistration.getRegistrationId(), principal.getName());
		StepVerifier.create(loadMono).expectNextCount(0).verifyComplete();
	}

	@Test
	public void setAuthorizedClientRowMapperWhenNullThenThrowIllegalArgumentException() {

		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.authorizedClientService.setAuthorizedClientRowMapper(null))
				.withMessageContaining("authorizedClientRowMapper cannot be nul");
	}

	@Test
	public void setAuthorizedClientParametersMapperWhenNullThenThrowIllegalArgumentException() {

		assertThatExceptionOfType(IllegalArgumentException.class)
				.isThrownBy(() -> this.authorizedClientService.setAuthorizedClientParametersMapper(null))
				.withMessageContaining("authorizedClientParametersMapper cannot be nul");
	}

	private static ConnectionFactory createDb() {
		ConnectionFactory connectionFactory = H2ConnectionFactory.inMemory("oauth-test");

		Mono.from(connectionFactory.create())
				.flatMapMany((connection) -> Flux
						.from(connection.createStatement("drop table oauth2_authorized_client").execute())
						.flatMap(Result::getRowsUpdated).onErrorResume((e) -> Mono.empty())
						.thenMany(connection.close()))
				.as(StepVerifier::create).verifyComplete();
		ConnectionFactoryInitializer createDb = createDb(OAUTH2_CLIENT_SCHEMA_SQL_RESOURCE);
		createDb.setConnectionFactory(connectionFactory);
		createDb.afterPropertiesSet();
		return connectionFactory;
	}

	private static ConnectionFactoryInitializer createDb(String schema) {
		ConnectionFactoryInitializer initializer = new ConnectionFactoryInitializer();

		CompositeDatabasePopulator populator = new CompositeDatabasePopulator();
		populator.addPopulators(new ResourceDatabasePopulator(new ClassPathResource(schema)));
		initializer.setDatabasePopulator(populator);
		return initializer;
	}

	private static Authentication createPrincipal() {
		return new TestingAuthenticationToken("principal-" + principalId++, "password");
	}

	private static OAuth2AuthorizedClient createAuthorizedClient(Authentication principal,
			ClientRegistration clientRegistration) {
		return createAuthorizedClient(principal, clientRegistration, false);
	}

	private static OAuth2AuthorizedClient createAuthorizedClient(Authentication principal,
			ClientRegistration clientRegistration, boolean requiredAttributesOnly) {
		OAuth2AccessToken accessToken;
		if (!requiredAttributesOnly) {
			accessToken = TestOAuth2AccessTokens.scopes("read", "write");
		}
		else {
			accessToken = TestOAuth2AccessTokens.noScopes();
		}
		OAuth2RefreshToken refreshToken = null;
		if (!requiredAttributesOnly) {
			refreshToken = TestOAuth2RefreshTokens.refreshToken();
		}
		return new OAuth2AuthorizedClient(clientRegistration, principal.getName(), accessToken, refreshToken);
	}

}
