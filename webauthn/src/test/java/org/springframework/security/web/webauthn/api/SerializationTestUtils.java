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

package org.springframework.security.web.webauthn.api;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.Serializable;

public final class SerializationTestUtils {

	private SerializationTestUtils() {
	}

	@SuppressWarnings("unchecked")
	public static <T extends Serializable> T serializeAndDeserialize(T object) {
		try {
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			try (ObjectOutputStream oos = new ObjectOutputStream(baos)) {
				oos.writeObject(object);
			}
			ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
			try (ObjectInputStream ois = new ObjectInputStream(bais)) {
				return (T) ois.readObject();
			}
		}
		catch (Exception ex) {
			throw new RuntimeException("Serialization round-trip failed", ex);
		}
	}

}
