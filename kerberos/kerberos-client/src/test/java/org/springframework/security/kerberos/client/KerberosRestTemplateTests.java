/*
 * Copyright 2004-present the original author or authors.
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

package org.springframework.security.kerberos.client;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.util.Collections;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okio.Buffer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.kerberos.test.KerberosSecurityTestcase;
import org.springframework.security.kerberos.test.MiniKdc;

import static org.assertj.core.api.Assertions.assertThat;

class KerberosRestTemplateTests extends KerberosSecurityTestcase {

	private final MockWebServer server = new MockWebServer();

	private static final String helloWorld = "Hello World";

	private static final MediaType textContentType = new MediaType("text", "plain",
			Collections.singletonMap("charset", "UTF-8"));

	private int port;

	private String baseUrl;

	private KerberosRestTemplate restTemplate;

	private String clientPrincipal;

	private File clientKeytab;

	@BeforeEach
	void setUp() throws Exception {
		this.server.setDispatcher(new TestDispatcher());
		this.server.start();
		this.port = this.server.getPort();
		this.baseUrl = "http://localhost:" + this.port;

		MiniKdc kdc = getKdc();
		File workDir = getWorkDir();

		this.clientPrincipal = "client/localhost";
		this.clientKeytab = new File(workDir, "client.keytab");
		kdc.createPrincipal(this.clientKeytab, this.clientPrincipal);

		String serverPrincipal = "HTTP/localhost";
		File serverKeytab = new File(workDir, "server.keytab");
		kdc.createPrincipal(serverKeytab, serverPrincipal);
	}

	@AfterEach
	void tearDown() throws Exception {
		this.server.shutdown();
	}

	@Test
	void sendsNegotiateHeader() {
		setUpClient();
		String s = this.restTemplate.getForObject(this.baseUrl + "/get", String.class);
		assertThat(s).isEqualTo(helloWorld);
	}

	private void setUpClient() {
		this.restTemplate = new KerberosRestTemplate(this.clientKeytab.getAbsolutePath(), this.clientPrincipal);
	}

	private MockResponse getRequest(RecordedRequest request, byte[] body, String contentType) {
		if (request.getMethod().equals("OPTIONS")) {
			return new MockResponse().setResponseCode(200).setHeader("Allow", "GET, OPTIONS, HEAD, TRACE");
		}
		Buffer buf = new Buffer();
		buf.write(body);
		MockResponse response = new MockResponse().setHeader(HttpHeaders.CONTENT_LENGTH, body.length)
			.setBody(buf)
			.setResponseCode(200);
		if (contentType != null) {
			response = response.setHeader(HttpHeaders.CONTENT_TYPE, contentType);
		}
		return response;
	}

	protected class TestDispatcher extends Dispatcher {

		@Override
		public MockResponse dispatch(RecordedRequest request) {
			try {
				byte[] helloWorldBytes = helloWorld.getBytes(StandardCharsets.UTF_8);

				if (request.getPath().equals("/get")) {
					String header = request.getHeader(HttpHeaders.AUTHORIZATION);
					if (header == null) {
						return new MockResponse().setResponseCode(401)
							.addHeader(HttpHeaders.WWW_AUTHENTICATE, "Negotiate");
					}
					else if (header.startsWith("Negotiate ")) {
						return getRequest(request, helloWorldBytes, textContentType.toString());
					}
				}
				return new MockResponse().setResponseCode(404);
			}
			catch (Throwable ex) {
				return new MockResponse().setResponseCode(500).setBody(ex.toString());
			}

		}

	}

}
