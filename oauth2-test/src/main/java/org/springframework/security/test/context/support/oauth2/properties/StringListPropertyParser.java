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

import java.util.Collections;
import java.util.List;

/**
 * Turns an annotation String value into a {@link java.util.List List&lt;String&gt;}
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
public class StringListPropertyParser implements PropertyParser<List<String>> {

	/**
	 * {@inheritDoc}
	 */
	@Override
	public List<String> parse(final String value) {
		return Collections.singletonList(value);
	}

}
