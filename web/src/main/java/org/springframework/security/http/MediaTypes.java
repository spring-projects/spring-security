/*
 * Copyright 2002-2021 the original author or authors.
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

package org.springframework.security.http;

import java.nio.charset.StandardCharsets;

import org.springframework.http.MediaType;

/**
 * This is a placeholder to allow an incremental update to Spring Framework 7.0.
 *
 * @deprecated For removal
 */
@Deprecated(since = "7.0.0", forRemoval = true)
public final class MediaTypes {

	public static final MediaType APPLICATION_JSON_UTF8 = new MediaType(MediaType.APPLICATION_JSON,
			StandardCharsets.UTF_8);

	public static final String APPLICATION_JSON_UTF8_VALUE = APPLICATION_JSON_UTF8.toString();

	private MediaTypes() {
	}

}
