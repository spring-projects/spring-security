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
package org.springframework.security.test.oauth2.support;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.util.StringUtils;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class CollectionsSupport {

	public static String nullIfEmpty(final String str) {
		return StringUtils.isEmpty(str) ? null : str;
	}

	public static final Map<String, Object>
			putIfNotEmpty(final String key, final String value, final Map<String, Object> map) {
		if (value != null && !value.isEmpty()) {
			map.put(key, value);
		}
		return map;
	}

	public static final Map<String, Object>
			putIfNotEmpty(final String key, final Collection<String> value, final Map<String, Object> map) {
		if (value != null && !value.isEmpty()) {
			map.put(key, value);
		}
		return map;
	}

	public static final Set<String> asSet(final String... values) {
		return values.length == 0 ? Collections.emptySet() : Stream.of(values).collect(Collectors.toSet());
	}

	public static final List<String> asList(final String... values) {
		return values.length == 0 ? Collections.emptyList() : Stream.of(values).collect(Collectors.toList());
	}

}
