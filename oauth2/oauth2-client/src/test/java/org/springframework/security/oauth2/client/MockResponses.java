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

package org.springframework.security.oauth2.client;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import okhttp3.mockwebserver.MockResponse;

import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;

/**
 * @author Steve Riesenberg
 */
public final class MockResponses {

	private MockResponses() {
	}

	public static MockResponse json(String path) {
		try {
			String json = new ClassPathResource(path).getContentAsString(StandardCharsets.UTF_8);
			return new MockResponse().setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
				.setBody(json);
		}
		catch (IOException ex) {
			throw new RuntimeException("Unable to read %s as a classpath resource".formatted(path), ex);
		}
	}

}
