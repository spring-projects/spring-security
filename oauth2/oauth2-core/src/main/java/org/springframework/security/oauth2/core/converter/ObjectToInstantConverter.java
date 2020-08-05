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
package org.springframework.security.oauth2.core.converter;

import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.GenericConverter;

import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.Set;

/**
 * @author Joe Grandja
 * @since 5.2
 */
final class ObjectToInstantConverter implements GenericConverter {

	@Override
	public Set<ConvertiblePair> getConvertibleTypes() {
		return Collections.singleton(new ConvertiblePair(Object.class, Instant.class));
	}

	@Override
	public Object convert(Object source, TypeDescriptor sourceType, TypeDescriptor targetType) {
		if (source == null) {
			return null;
		}
		if (source instanceof Instant) {
			return source;
		}
		if (source instanceof Date) {
			return ((Date) source).toInstant();
		}
		if (source instanceof Number) {
			return Instant.ofEpochSecond(((Number) source).longValue());
		}
		try {
			return Instant.ofEpochSecond(Long.parseLong(source.toString()));
		}
		catch (Exception ex) {
			// Ignore
		}
		try {
			return Instant.parse(source.toString());
		}
		catch (Exception ex) {
			// Ignore
		}
		return null;
	}

}
