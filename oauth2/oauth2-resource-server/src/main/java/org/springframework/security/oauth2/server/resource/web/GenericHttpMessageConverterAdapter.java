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

package org.springframework.security.oauth2.server.resource.web;

import java.io.IOException;
import java.lang.reflect.Type;
import java.util.List;

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
 * {@link GenericHttpMessageConverter} implementation that delegates to a
 * {@link SmartHttpMessageConverter}.
 *
 * @param <T> the converted object type
 * @author Sebastien Deleuze
 * @since 7.0
 */
final class GenericHttpMessageConverterAdapter<T> implements GenericHttpMessageConverter<T> {

	private final SmartHttpMessageConverter<T> smartConverter;

	GenericHttpMessageConverterAdapter(SmartHttpMessageConverter<T> smartConverter) {
		this.smartConverter = smartConverter;
	}

	@Override
	public boolean canRead(Type type, @Nullable Class<?> contextClass, @Nullable MediaType mediaType) {
		return this.smartConverter.canRead(ResolvableType.forType(type), mediaType);
	}

	@Override
	public T read(Type type, @Nullable Class<?> contextClass, HttpInputMessage inputMessage)
			throws IOException, HttpMessageNotReadableException {
		return this.smartConverter.read(ResolvableType.forType(type), inputMessage, null);
	}

	@Override
	public boolean canWrite(@Nullable Type type, Class<?> clazz, @Nullable MediaType mediaType) {
		return this.smartConverter.canWrite(ResolvableType.forType(type), clazz, mediaType);
	}

	@Override
	public void write(T t, @Nullable Type type, @Nullable MediaType contentType, HttpOutputMessage outputMessage)
			throws IOException, HttpMessageNotWritableException {
		this.smartConverter.write(t, ResolvableType.forType(type), contentType, outputMessage, null);
	}

	@Override
	public boolean canRead(Class<?> clazz, @Nullable MediaType mediaType) {
		return this.smartConverter.canRead(ResolvableType.forClass(clazz), mediaType);
	}

	@Override
	public boolean canWrite(Class<?> clazz, @Nullable MediaType mediaType) {
		return this.smartConverter.canWrite(clazz, mediaType);
	}

	@Override
	public List<MediaType> getSupportedMediaTypes() {
		return this.smartConverter.getSupportedMediaTypes();
	}

	@Override
	public T read(Class<? extends T> clazz, HttpInputMessage inputMessage)
			throws IOException, HttpMessageNotReadableException {
		return this.smartConverter.read(clazz, inputMessage);
	}

	@Override
	public void write(T t, @Nullable MediaType contentType, HttpOutputMessage outputMessage)
			throws IOException, HttpMessageNotWritableException {
		this.smartConverter.write(t, contentType, outputMessage);
	}

}
