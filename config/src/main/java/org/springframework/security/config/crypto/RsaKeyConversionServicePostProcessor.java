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

package org.springframework.security.config.crypto;

import java.beans.PropertyEditor;
import java.beans.PropertyEditorSupport;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.BeansException;
import org.springframework.beans.factory.config.BeanFactoryPostProcessor;
import org.springframework.beans.factory.config.ConfigurableListableBeanFactory;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.security.converter.RsaKeyConverters;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * Adds {@link RsaKeyConverters} to the configured {@link ConversionService} or
 * {@link PropertyEditor}s
 *
 * @author Josh Cummings
 * @since 5.2
 */
public class RsaKeyConversionServicePostProcessor implements BeanFactoryPostProcessor {

	private static final String CONVERSION_SERVICE_BEAN_NAME = "conversionService";

	private ResourceLoader resourceLoader = new DefaultResourceLoader();

	public void setResourceLoader(ResourceLoader resourceLoader) {
		Assert.notNull(resourceLoader, "resourceLoader cannot be null");
		this.resourceLoader = resourceLoader;
	}

	/**
	 * {@inheritDoc}
	 */
	@Override
	public void postProcessBeanFactory(ConfigurableListableBeanFactory beanFactory) throws BeansException {
		if (hasUserDefinedConversionService(beanFactory)) {
			return;
		}

		Converter<String, RSAPrivateKey> pkcs8 = pkcs8();
		Converter<String, RSAPublicKey> x509 = x509();

		ConversionService service = beanFactory.getConversionService();
		if (service instanceof ConverterRegistry) {
			ConverterRegistry registry = (ConverterRegistry) service;
			registry.addConverter(String.class, RSAPrivateKey.class, pkcs8);
			registry.addConverter(String.class, RSAPublicKey.class, x509);
		}
		else {
			beanFactory.addPropertyEditorRegistrar((registry) -> {
				registry.registerCustomEditor(RSAPublicKey.class, new ConverterPropertyEditorAdapter<>(x509));
				registry.registerCustomEditor(RSAPrivateKey.class, new ConverterPropertyEditorAdapter<>(pkcs8));
			});
		}
	}

	private boolean hasUserDefinedConversionService(ConfigurableListableBeanFactory beanFactory) {
		return beanFactory.containsBean(CONVERSION_SERVICE_BEAN_NAME)
				&& beanFactory.isTypeMatch(CONVERSION_SERVICE_BEAN_NAME, ConversionService.class);
	}

	private Converter<String, RSAPrivateKey> pkcs8() {
		Converter<String, InputStream> pemInputStreamConverter = pemInputStreamConverter();
		Converter<InputStream, RSAPrivateKey> pkcs8KeyConverter = autoclose(RsaKeyConverters.pkcs8());
		return pair(pemInputStreamConverter, pkcs8KeyConverter);
	}

	private Converter<String, RSAPublicKey> x509() {
		Converter<String, InputStream> pemInputStreamConverter = pemInputStreamConverter();
		Converter<InputStream, RSAPublicKey> x509KeyConverter = autoclose(RsaKeyConverters.x509());
		return pair(pemInputStreamConverter, x509KeyConverter);
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

	private <S, T, I> Converter<S, T> pair(Converter<S, I> one, Converter<I, T> two) {
		return (source) -> {
			I intermediary = one.convert(source);
			return two.convert(intermediary);
		};
	}

	private static class ConverterPropertyEditorAdapter<T> extends PropertyEditorSupport {

		private final Converter<String, T> converter;

		ConverterPropertyEditorAdapter(Converter<String, T> converter) {
			this.converter = converter;
		}

		@Override
		public String getAsText() {
			return null;
		}

		@Override
		public void setAsText(String text) throws IllegalArgumentException {
			if (StringUtils.hasText(text)) {
				setValue(this.converter.convert(text));
			}
			else {
				setValue(null);
			}
		}

	}

}
