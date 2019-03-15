/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.web.header.writers;

/**
 * A {@link StaticHeadersWriter} that inserts headers to prevent content sniffing.
 * Specifically the following headers are set:
 * <ul>
 * <li>X-Content-Type-Options: nosniff</li>
 * </ul>
 *
 * @author Rob Winch
 * @since 3.2
 */
public final class XContentTypeOptionsHeaderWriter extends StaticHeadersWriter {

	/**
	 * Creates a new instance
	 */
	public XContentTypeOptionsHeaderWriter() {
		super("X-Content-Type-Options", "nosniff");
	}
}
