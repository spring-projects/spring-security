/*
 * Copyright 2002-present the original author or authors.
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

package org.springframework.security.oauth2.core;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Objects;

import org.jspecify.annotations.Nullable;

import org.springframework.core.ResolvableType;
import org.springframework.http.HttpInputMessage;
import org.springframework.http.HttpOutputMessage;
import org.springframework.http.MediaType;
import org.springframework.http.converter.GenericHttpMessageConverter;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.http.converter.HttpMessageNotWritableException;
import org.springframework.http.converter.SmartHttpMessageConverter;

/**
 * Adapter that exposes a {@link GenericHttpMessageConverter} as a
 * {@link SmartHttpMessageConverter}. Delegates read and write operations with support for
 * parameterized types.
 *
 * @param <T> the type of objects to convert
 * @author Andrey Litvitski
 * @since 7.0.0
 */
public class SmartGenericHttpMessageConverterAdapter<T> implements SmartHttpMessageConverter<T> {

	private final GenericHttpMessageConverter<T> genericHttpMessageConverter;

	public SmartGenericHttpMessageConverterAdapter(GenericHttpMessageConverter<T> genericHttpMessageConverter) {
		this.genericHttpMessageConverter = genericHttpMessageConverter;
	}

	@Override
	public boolean canRead(ResolvableType type, @Nullable MediaType mediaType) {
		return this.genericHttpMessageConverter.canRead(Objects.requireNonNull(type.getRawClass()), mediaType);
	}

	@Override
	public T read(ResolvableType type, HttpInputMessage inputMessage, @Nullable Map<String, Object> hints)
			throws IOException, HttpMessageNotReadableException {
		return this.genericHttpMessageConverter.read(type.getType(), null, inputMessage);
	}

	@Override
	public boolean canWrite(ResolvableType targetType, Class<?> valueClass, @Nullable MediaType mediaType) {
		return this.genericHttpMessageConverter.canWrite(Objects.requireNonNull(targetType.getRawClass()), mediaType);
	}

	@Override
	public void write(T t, ResolvableType type, @Nullable MediaType contentType, HttpOutputMessage outputMessage,
			@Nullable Map<String, Object> hints) throws IOException, HttpMessageNotWritableException {
		this.genericHttpMessageConverter.write(t, type.getType(), contentType, outputMessage);
	}

	@Override
	public List<MediaType> getSupportedMediaTypes() {
		return this.genericHttpMessageConverter.getSupportedMediaTypes();
	}

}
