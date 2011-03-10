/*
 * Copyright 2011 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.springframework.security.crypto.keygen;

import static org.springframework.security.crypto.util.EncodingUtils.hexEncode;

/**
 * A StringKeyGenerator that generates hex-encoded String keys.
 * Delegates to a {@link BytesKeyGenerator} for the actual key generation.
 * @author Keith Donald
 */
final class HexEncodingStringKeyGenerator implements StringKeyGenerator {

    private final BytesKeyGenerator keyGenerator;

    public HexEncodingStringKeyGenerator(BytesKeyGenerator keyGenerator) {
        this.keyGenerator = keyGenerator;
    }

    public String generateKey() {
        return hexEncode(keyGenerator.generateKey());
    }

}