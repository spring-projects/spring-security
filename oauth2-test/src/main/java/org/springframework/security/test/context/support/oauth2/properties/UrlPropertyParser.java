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
package org.springframework.security.test.context.support.oauth2.properties;

import java.net.MalformedURLException;
import java.net.URL;

/**
 * Turns an annotation String value into an {@link java.net.URL URL}
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
public class UrlPropertyParser implements PropertyParser<URL> {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public URL parse(String value) {
		try {
			return new URL(value);
		}
		catch (MalformedURLException e) {
			throw new RuntimeException(e);
		}
	}

}
