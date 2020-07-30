/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.acls.jdbc;

import java.io.Serializable;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.UUID;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.springframework.core.convert.ConversionFailedException;
import org.springframework.core.convert.ConversionService;
import org.springframework.core.convert.TypeDescriptor;
import org.springframework.core.convert.converter.Converter;
import org.springframework.core.convert.support.GenericConversionService;
import org.springframework.security.acls.model.ObjectIdentity;
import org.springframework.util.Assert;

/**
 * Utility class for helping convert database representations of
 * {@link ObjectIdentity#getIdentifier()} into the correct Java type as specified by
 * <code>acl_class.class_id_type</code>.
 *
 * @author paulwheeler
 */
class AclClassIdUtils {

	private static final String DEFAULT_CLASS_ID_TYPE_COLUMN_NAME = "class_id_type";

	private static final Log log = LogFactory.getLog(AclClassIdUtils.class);

	private ConversionService conversionService;

	AclClassIdUtils() {
		GenericConversionService genericConversionService = new GenericConversionService();
		genericConversionService.addConverter(String.class, Long.class, new StringToLongConverter());
		genericConversionService.addConverter(String.class, UUID.class, new StringToUUIDConverter());
		this.conversionService = genericConversionService;
	}

	AclClassIdUtils(ConversionService conversionService) {
		Assert.notNull(conversionService, "conversionService must not be null");
		this.conversionService = conversionService;
	}

	/**
	 * Converts the raw type from the database into the right Java type. For most
	 * applications the 'raw type' will be Long, for some applications it could be String.
	 * @param identifier The identifier from the database
	 * @param resultSet Result set of the query
	 * @return The identifier in the appropriate target Java type. Typically Long or UUID.
	 * @throws SQLException
	 */
	Serializable identifierFrom(Serializable identifier, ResultSet resultSet) throws SQLException {
		if (isString(identifier) && hasValidClassIdType(resultSet)
				&& canConvertFromStringTo(classIdTypeFrom(resultSet))) {
			return convertFromStringTo((String) identifier, classIdTypeFrom(resultSet));
		}
		// Assume it should be a Long type
		return convertToLong(identifier);
	}

	private boolean hasValidClassIdType(ResultSet resultSet) {
		try {
			return classIdTypeFrom(resultSet) != null;
		}
		catch (SQLException ex) {
			log.debug("Unable to obtain the class id type", ex);
			return false;
		}
	}

	private <T extends Serializable> Class<T> classIdTypeFrom(ResultSet resultSet) throws SQLException {
		return classIdTypeFrom(resultSet.getString(DEFAULT_CLASS_ID_TYPE_COLUMN_NAME));
	}

	private <T extends Serializable> Class<T> classIdTypeFrom(String className) {
		if (className == null) {
			return null;
		}
		try {
			return (Class) Class.forName(className);
		}
		catch (ClassNotFoundException ex) {
			log.debug("Unable to find class id type on classpath", ex);
			return null;
		}
	}

	private <T> boolean canConvertFromStringTo(Class<T> targetType) {
		return this.conversionService.canConvert(String.class, targetType);
	}

	private <T extends Serializable> T convertFromStringTo(String identifier, Class<T> targetType) {
		return this.conversionService.convert(identifier, targetType);
	}

	/**
	 * Converts to a {@link Long}, attempting to use the {@link ConversionService} if
	 * available.
	 * @param identifier The identifier
	 * @return Long version of the identifier
	 * @throws NumberFormatException if the string cannot be parsed to a long.
	 * @throws org.springframework.core.convert.ConversionException if a conversion
	 * exception occurred
	 * @throws IllegalArgumentException if targetType is null
	 */
	private Long convertToLong(Serializable identifier) {
		if (this.conversionService.canConvert(identifier.getClass(), Long.class)) {
			return this.conversionService.convert(identifier, Long.class);
		}
		return Long.valueOf(identifier.toString());
	}

	private boolean isString(Serializable object) {
		return object.getClass().isAssignableFrom(String.class);
	}

	void setConversionService(ConversionService conversionService) {
		Assert.notNull(conversionService, "conversionService must not be null");
		this.conversionService = conversionService;
	}

	private static class StringToLongConverter implements Converter<String, Long> {

		@Override
		public Long convert(String identifierAsString) {
			if (identifierAsString == null) {
				throw new ConversionFailedException(TypeDescriptor.valueOf(String.class),
						TypeDescriptor.valueOf(Long.class), null, null);

			}
			return Long.parseLong(identifierAsString);
		}

	}

	private static class StringToUUIDConverter implements Converter<String, UUID> {

		@Override
		public UUID convert(String identifierAsString) {
			if (identifierAsString == null) {
				throw new ConversionFailedException(TypeDescriptor.valueOf(String.class),
						TypeDescriptor.valueOf(UUID.class), null, null);

			}
			return UUID.fromString(identifierAsString);
		}

	}

}
