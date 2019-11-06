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

	// introspection endpoint

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
			"{ \"message\" : \"This mock authorization server responds to just two requests: POST /introspect" +
					" and GET /.well-known/jwks.json.\" }",
			404
	);

	// jwks endpoint

	private static final MockResponse JWKS_RESPONSE = response(
			"{\"keys\":[{\"p\":\"2p-ViY7DE9ZrdWQb544m0Jp7Cv03YCSljqfim9pD4ALhObX0OrAznOiowTjwBky9JGffMwDBVSfJSD9TSU7aH2sbbfi0bZLMdekKAuimudXwUqPDxrrg0BCyvCYgLmKjbVT3zcdylWSog93CNTxGDPzauu-oc0XPNKCXnaDpNvE\",\"kty\":\"RSA\",\"q\":\"sP_QYavrpBvSJ86uoKVGj2AGl78CSsAtpf1ybSY5TwUlorXSdqapRbY69Y271b0aMLzlleUn9ZTBO1dlKV2_dw_lPADHVia8z3pxL-8sUhIXLsgj4acchMk4c9YX-sFh07xENnyZ-_TXm3llPLuL67HUfBC2eKe800TmCYVWc9U\",\"d\":\"bn1nFxCQT4KLTHqo8mo9HvHD0cRNRNdWcKNnnEQkCF6tKbt-ILRyQGP8O40axLd7CoNVG9c9p_-g4-2kwCtLJNv_STLtwfpCY7VN5o6-ZIpfTjiW6duoPrLWq64Hm_4LOBQTiZfUPcLhsuJRHbWqakj-kV_YbUyC2Ocf_dd8IAQcSrAU2SCcDebhDCWwRUFvaa9V5eq0851S9goaA-AJz-JXyePH6ZFr8JxmWkWxYZ5kdcMD-sm9ZbxE0CaEk32l4fE4hR-L8x2dDtjWA-ahKCZ091z-gV3HWtR2JOjvxoNRjxUo3UxaGiFJHWNIl0EYUJZu1Cb-5wIlEI7wPx5mwQ\",\"e\":\"AQAB\",\"use\":\"sig\",\"kid\":\"one\",\"qi\":\"qS0OK48M2CIAA6_4Wdw4EbCaAfcTLf5Oy9t5BOF_PFUKqoSpZ6JsT5H0a_4zkjt-oI969v78OTlvBKbmEyKO-KeytzHBAA5CsLmVcz0THrMSg6oXZqu66MPnvWoZN9FEN5TklPOvBFm8Bg1QZ3k-YMVaM--DLvhaYR95_mqaz50\",\"dp\":\"Too2NozLGD1XrXyhabZvy1E0EuaVFj0UHQPDLSpkZ_2g3BK6Art6T0xmE8RYtmqrKIEIdlI3IliAvyvAx_1D7zWTTRaj-xlZyqJFrnXWL7zj8UxT8PkB-r2E-ILZ3NAi1gxIWezlBTZ8M6NfObDFmbTc_3tJkN_raISo8z_ziIE\",\"dq\":\"U0yhSkY5yOsa9YcMoigGVBWSJLpNHtbg5NypjHrPv8OhWbkOSq7WvSstBkFk5AtyFvvfZLMLIkWWxxGzV0t6f1MoxBtttLrYYyCxwihiiGFhLbAdSuZ1wnxcqA9bC7UVECvrQmVTpsMs8UupfHKbQBpZ8OWAqrnuYNNtG4_4Bt0\",\"n\":\"lygtuZj0lJjqOqIWocF8Bb583QDdq-aaFg8PesOp2-EDda6GqCpL-_NZVOflNGX7XIgjsWHcPsQHsV9gWuOzSJ0iEuWvtQ6eGBP5M6m7pccLNZfwUse8Cb4Ngx3XiTlyuqM7pv0LPyppZusfEHVEdeelou7Dy9k0OQ_nJTI3b2E1WBoHC58CJ453lo4gcBm1efURN3LIVc1V9NQY_ESBKVdwqYyoJPEanURLVGRd6cQKn6YrCbbIRHjqAyqOE-z3KmgDJnPriljfR5XhSGyM9eqD9Xpy6zu_MAeMJJfSArp857zLPk-Wf5VP9STAcjyfdBIybMKnwBYr2qHMT675hQ\"}]}",
			200
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
	 * Get's the URL (i.e. "http://localhost:123456")
	 * @return
	 */
	private String getUrl() {
		MockWebServer mockWebServer = getSource();
		if (!this.started) {
			intializeMockWebServer(mockWebServer);
		}
		String url = mockWebServer.url("").url().toExternalForm();
		return url.substring(0, url.length() - 1);
	}

	private void intializeMockWebServer(MockWebServer mockWebServer) {
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
		if ("/.well-known/jwks.json".equals(request.getPath())) {
			return JWKS_RESPONSE;
		}

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
