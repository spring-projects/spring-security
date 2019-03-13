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
package org.springframework.security.test.context.support.oauth2;

import java.net.MalformedURLException;
import java.net.URL;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 *
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 *
 */
class StringParsingHelper {

	public static String nullIfEmpty(String str) {
		return str == null || str.isEmpty() ? null : str;
	}

	public static Instant intant(String str) {
		return str == null || str.isEmpty() ? null : Instant.parse(str);
	}

	public static URL url(String str) throws MalformedURLException {
		return str == null || str.isEmpty() ? null : new URL(str);
	}

	public static List<String> stringList(String[] stringArr) {
		return Stream.of(stringArr).collect(Collectors.toList());
	}

	public static Set<String> stringSet(String[] stringArr) {
		return Stream.of(stringArr).collect(Collectors.toSet());
	}

	public static Set<SimpleGrantedAuthority> grantedAuthorities(String[] stringArr) {
		return Stream.of(stringArr).map(SimpleGrantedAuthority::new)
				.collect(Collectors.toSet());
	}

}