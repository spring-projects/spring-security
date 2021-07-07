/*
 * Copyright 2008 the original author or authors.
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

package org.springframework.security.core;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.security.AccessController;
import java.security.PrivilegedAction;

import sun.misc.Unsafe;

import org.springframework.objenesis.instantiator.util.UnsafeUtils;

/**
 * Used for setting static variables even if they are private static final.
 *
 * The code in this class has been adopted from Powermock's <a href=
 * "https://github.com/noushadali/powermock/blob/powermock-1.5.4/reflect/src/main/java/org/powermock/reflect/internal/WhiteboxImpl.java#L326">WhiteboxImpl</a>.
 *
 * @author Rob Winch
 */
final class StaticFinalReflectionUtils {

	/**
	 * Used to support setting static fields that are final using Java's Unsafe. If the
	 * field is not static final, use
	 * {@link org.springframework.test.util.ReflectionTestUtils}.
	 * @param field the field to set
	 * @param newValue the new value
	 */
	static void setField(final Field field, final Object newValue) {
		try {
			field.setAccessible(true);
			int fieldModifiersMask = field.getModifiers();
			boolean isFinalModifierPresent = (fieldModifiersMask & Modifier.FINAL) == Modifier.FINAL;
			if (isFinalModifierPresent) {
				AccessController.doPrivileged(new PrivilegedAction<Object>() {
					@Override
					public Object run() {
						try {
							Unsafe unsafe = UnsafeUtils.getUnsafe();
							long offset = unsafe.staticFieldOffset(field);
							Object base = unsafe.staticFieldBase(field);
							setFieldUsingUnsafe(base, field.getType(), offset, newValue, unsafe);
							return null;
						}
						catch (Throwable thrown) {
							throw new RuntimeException(thrown);
						}
					}
				});
			}
			else {
				field.set(null, newValue);
			}
		}
		catch (SecurityException ex) {
			throw new RuntimeException(ex);
		}
		catch (IllegalAccessException ex) {
			throw new RuntimeException(ex);
		}
		catch (IllegalArgumentException ex) {
			throw new RuntimeException(ex);
		}
	}

	private static void setFieldUsingUnsafe(Object base, Class type, long offset, Object newValue, Unsafe unsafe) {
		if (type == Integer.TYPE) {
			unsafe.putInt(base, offset, ((Integer) newValue));
		}
		else if (type == Short.TYPE) {
			unsafe.putShort(base, offset, ((Short) newValue));
		}
		else if (type == Long.TYPE) {
			unsafe.putLong(base, offset, ((Long) newValue));
		}
		else if (type == Byte.TYPE) {
			unsafe.putByte(base, offset, ((Byte) newValue));
		}
		else if (type == Boolean.TYPE) {
			unsafe.putBoolean(base, offset, ((Boolean) newValue));
		}
		else if (type == Float.TYPE) {
			unsafe.putFloat(base, offset, ((Float) newValue));
		}
		else if (type == Double.TYPE) {
			unsafe.putDouble(base, offset, ((Double) newValue));
		}
		else if (type == Character.TYPE) {
			unsafe.putChar(base, offset, ((Character) newValue));
		}
		else {
			unsafe.putObject(base, offset, newValue);
		}
	}

	private StaticFinalReflectionUtils() {
	}

}
