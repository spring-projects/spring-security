/*
 * Copyright 2011-2016 the original author or authors.
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

package org.springframework.security.crypto.keygen;

/**
 * Key generator that simply returns the same key every time.
 *
 * @author Keith Donald
 * @author Annabelle Donald
 * @author Corgan Donald
 */
final class SharedKeyGenerator implements BytesKeyGenerator {

	private byte[] sharedKey;

	SharedKeyGenerator(byte[] sharedKey) {
		this.sharedKey = sharedKey;
	}

	@Override
	public int getKeyLength() {
		return this.sharedKey.length;
	}

	@Override
	public byte[] generateKey() {
		return this.sharedKey;
	}

}
