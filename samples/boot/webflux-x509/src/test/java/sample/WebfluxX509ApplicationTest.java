/*
 * Copyright 2002-2018 the original author or authors.
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

package sample;

import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContextBuilder;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.web.server.LocalServerPort;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.client.reactive.ClientHttpConnector;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.netty.http.client.HttpClient;

import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class WebfluxX509ApplicationTest {

	@LocalServerPort
	int port;

	@Test
	public void shouldExtractAuthenticationFromCertificate() throws Exception {
		WebTestClient webTestClient = createWebTestClientWithClientCertificate();
		webTestClient
				.get().uri("/me")
				.exchange()
				.expectStatus().isOk()
				.expectBody()
				.consumeWith(result -> {
					String responseBody = new String(result.getResponseBody());
					assertThat(responseBody).contains("Hello, client");
				});
	}

	private WebTestClient createWebTestClientWithClientCertificate() throws KeyStoreException, IOException, NoSuchAlgorithmException, CertificateException, UnrecoverableEntryException {
		ClassPathResource serverKeystore = new ClassPathResource("/certs/server.p12");

		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		keyStore.load(serverKeystore.getInputStream(), "password".toCharArray());

		X509Certificate devCA = (X509Certificate) keyStore.getCertificate("DevCA");

		X509Certificate clientCrt = (X509Certificate) keyStore.getCertificate("client");
		KeyStore.Entry keyStoreEntry = keyStore.getEntry("client",
				new KeyStore.PasswordProtection("password".toCharArray()));
		PrivateKey clientKey = ((KeyStore.PrivateKeyEntry) keyStoreEntry).getPrivateKey();

		SslContextBuilder sslContextBuilder = SslContextBuilder
				.forClient().clientAuth(ClientAuth.REQUIRE)
				.trustManager(devCA)
				.keyManager(clientKey, clientCrt);

		HttpClient httpClient = HttpClient.create().secure(sslContextSpec -> sslContextSpec.sslContext(sslContextBuilder));
		ClientHttpConnector httpConnector = new ReactorClientHttpConnector(httpClient);

		return WebTestClient
				.bindToServer(httpConnector)
				.baseUrl("https://localhost:" + port)
				.build();
	}
}
