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

package org.springframework.security.authentication.apikey;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/**
 * Converts API key claims to a collection of {@link SimpleGrantedAuthority}.
 *
 * @author Alexey Razinkov
 */
public class ApiKeySimpleGrantedAuthorityConverter implements Converter<StoredApiKey, Collection<GrantedAuthority>> {

	@Override
	public Collection<GrantedAuthority> convert(StoredApiKey source) {
		final List<GrantedAuthority> result = new ArrayList<>();
		for (final String claim : source.claims()) {
			result.add(new SimpleGrantedAuthority(claim));
		}
		return result;
	}

}
