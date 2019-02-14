/*
 * Copyright 2002-2019 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.springframework.boot.env;

import java.io.IOException;
import java.util.Base64;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import okhttp3.mockwebserver.Dispatcher;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.MockWebServer;
import okhttp3.mockwebserver.RecordedRequest;
import okio.Buffer;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.beans.factory.DisposableBean;
import org.springframework.core.env.PropertySource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/**
 * @author Rob Winch
 */
public class MockWebServerPropertySource extends PropertySource<MockWebServer> implements
		DisposableBean {

	private static final MockResponse NO_SCOPES_RESPONSE = response(
			"{\n" +
					"      \"active\": true,\n" +
					"      \"sub\": \"subject\"\n" +
					"     }",
			200
	);

	private static final MockResponse MESSASGE_READ_SCOPE_RESPONSE = response(
			"{\n" +
					"      \"active\": true,\n" +
					"      \"scope\" : \"message:read\"," +
					"      \"sub\": \"subject\"\n" +
					"     }",
			200
	);

	private static final MockResponse INACTIVE_RESPONSE = response(
			"{\n" +
					"      \"active\": false,\n" +
					"     }",
			200
	);

	private static final MockResponse BAD_REQUEST_RESPONSE = response(
			"{ \"message\" : \"This mock authorization server requires a username and password of " +
					"client/secret and a POST body of token=${token}\" }",
			400
	);

	private static final MockResponse NOT_FOUND_RESPONSE = response(
			"{ \"message\" : \"This mock authorization server responds to just one request: POST /introspect.\" }",
			404
	);

	/**
	 * Name of the random {@link PropertySource}.
	 */
	public static final String MOCK_WEB_SERVER_PROPERTY_SOURCE_NAME = "mockwebserver";

	private static final String NAME = "mockwebserver.url";

	private static final Log logger = LogFactory.getLog(MockWebServerPropertySource.class);

	private boolean started;

	public MockWebServerPropertySource() {
		super(MOCK_WEB_SERVER_PROPERTY_SOURCE_NAME, new MockWebServer());
	}

	@Override
	public Object getProperty(String name) {
		if (!name.equals(NAME)) {
			return null;
		}
		if (logger.isTraceEnabled()) {
			logger.trace("Looking up the url for '" + name + "'");
		}
		String url = getUrl();
		return url;
	}

	@Override
	public void destroy() throws Exception {
		getSource().shutdown();
	}

	/**
	 * Get's the URL (e.g. "http://localhost:123456")
	 * @return
	 */
	private String getUrl() {
		MockWebServer mockWebServer = getSource();
		if (!this.started) {
			initializeMockWebServer(mockWebServer);
		}
		String url = mockWebServer.url("").url().toExternalForm();
		return url.substring(0, url.length() - 1);
	}

	private void initializeMockWebServer(MockWebServer mockWebServer) {
		Dispatcher dispatcher = new Dispatcher() {
			@Override
			public MockResponse dispatch(RecordedRequest request) {
				return doDispatch(request);
			}
		};

		mockWebServer.setDispatcher(dispatcher);
		try {
			mockWebServer.start();
			this.started = true;
		} catch (IOException e) {
			throw new RuntimeException("Could not start " + mockWebServer, e);
		}
	}

	private MockResponse doDispatch(RecordedRequest request) {
		if ("/introspect".equals(request.getPath())) {
			return Optional.ofNullable(request.getHeader(HttpHeaders.AUTHORIZATION))
					.filter(authorization -> isAuthorized(authorization, "client", "secret"))
					.map(authorization -> parseBody(request.getBody()))
					.map(parameters -> parameters.get("token"))
					.map(token -> {
						if ("00ed5855-1869-47a0-b0c9-0f3ce520aee7".equals(token)) {
							return NO_SCOPES_RESPONSE;
						} else if ("b43d1500-c405-4dc9-b9c9-6cfd966c34c9".equals(token)) {
							return MESSASGE_READ_SCOPE_RESPONSE;
						} else {
							return INACTIVE_RESPONSE;
						}
					})
					.orElse(BAD_REQUEST_RESPONSE);
		}

		return NOT_FOUND_RESPONSE;
	}

	private boolean isAuthorized(String authorization, String username, String password) {
		String[] values = new String(Base64.getDecoder().decode(authorization.substring(6))).split(":");
		return username.equals(values[0]) && password.equals(values[1]);
	}

	private Map<String, Object> parseBody(Buffer body) {
		return Stream.of(body.readUtf8().split("&"))
				.map(parameter -> parameter.split("="))
				.collect(Collectors.toMap(parts -> parts[0], parts -> parts[1]));
	}

	private static MockResponse response(String body, int status) {
		return new MockResponse()
				.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setResponseCode(status)
				.setBody(body);
	}

}
