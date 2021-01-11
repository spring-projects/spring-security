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

package org.springframework.security.converter;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.Key;

import org.springframework.core.convert.converter.Converter;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.util.Assert;

/**
 * Adapts any {@link Key} {@link Converter} into once that will first extract that key
 * from a resource.
 *
 * By default, keys can be read from the file system, the classpath, and from HTTP
 * endpoints. This can be customized by providing a {@link ResourceLoader}
 *
 * @author Josh Cummings
 * @since 5.5
 */
public class ResourceKeyConverterAdapter<T extends Key> implements Converter<String, T> {

	private ResourceLoader resourceLoader = new DefaultResourceLoader();

	private final Converter<String, T> delegate;

	/**
	 * Construct a {@link ResourceKeyConverterAdapter} with the provided parameters
	 * @param delegate converts a stream of key material into a {@link Key}
	 */
	public ResourceKeyConverterAdapter(Converter<InputStream, T> delegate) {
		this.delegate = pemInputStreamConverter().andThen(autoclose(delegate));
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public T convert(String source) {
		return this.delegate.convert(source);
	}

	/**
	 * Use this {@link ResourceLoader} to read the key material
	 * @param resourceLoader the {@link ResourceLoader} to use
	 */
	public void setResourceLoader(ResourceLoader resourceLoader) {
		Assert.notNull(resourceLoader, "resourceLoader cannot be null");
		this.resourceLoader = resourceLoader;
	}

	private Converter<String, InputStream> pemInputStreamConverter() {
		return (source) -> source.startsWith("-----") ? toInputStream(source)
				: toInputStream(this.resourceLoader.getResource(source));
	}

	private InputStream toInputStream(String raw) {
		return new ByteArrayInputStream(raw.getBytes(StandardCharsets.UTF_8));
	}

	private InputStream toInputStream(Resource resource) {
		try {
			return resource.getInputStream();
		}
		catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}

	private <T> Converter<InputStream, T> autoclose(Converter<InputStream, T> inputStreamKeyConverter) {
		return (inputStream) -> {
			try (InputStream is = inputStream) {
				return inputStreamKeyConverter.convert(is);
			}
			catch (IOException ex) {
				throw new UncheckedIOException(ex);
			}
		};
	}

}
