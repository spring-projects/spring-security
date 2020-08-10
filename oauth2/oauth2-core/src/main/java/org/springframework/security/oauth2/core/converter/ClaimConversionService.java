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

import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.converter.ConverterRegistry;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.security.oauth2.core.ClaimAccessor;

/**
 * A {@link ConversionService} configured with converters that provide type conversion for
 * claim values.
 *
 * @author Joe Grandja
 * @since 5.2
 * @see GenericConversionService
 * @see ClaimAccessor
 */
public final class ClaimConversionService extends GenericConversionService {

	private static volatile ClaimConversionService sharedInstance;

	private ClaimConversionService() {
		addConverters(this);
	}

	/**
	 * Returns a shared instance of {@code ClaimConversionService}.
	 * @return a shared instance of {@code ClaimConversionService}
	 */
	public static ClaimConversionService getSharedInstance() {
		ClaimConversionService sharedInstance = ClaimConversionService.sharedInstance;
		if (sharedInstance == null) {
			synchronized (ClaimConversionService.class) {
				sharedInstance = ClaimConversionService.sharedInstance;
				if (sharedInstance == null) {
					sharedInstance = new ClaimConversionService();
					ClaimConversionService.sharedInstance = sharedInstance;
				}
			}
		}
		return sharedInstance;
	}

	/**
	 * Adds the converters that provide type conversion for claim values to the provided
	 * {@link ConverterRegistry}.
	 * @param converterRegistry the registry of converters to add to
	 */
	public static void addConverters(ConverterRegistry converterRegistry) {
		converterRegistry.addConverter(new ObjectToStringConverter());
		converterRegistry.addConverter(new ObjectToBooleanConverter());
		converterRegistry.addConverter(new ObjectToInstantConverter());
		converterRegistry.addConverter(new ObjectToURLConverter());
		converterRegistry.addConverter(new ObjectToListStringConverter());
		converterRegistry.addConverter(new ObjectToMapStringObjectConverter());
	}

}
