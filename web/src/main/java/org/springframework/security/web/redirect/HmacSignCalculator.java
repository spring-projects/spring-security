/*
 * Copyright 2002-2016 the original author or authors.
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

package org.springframework.security.web.redirect;

import org.apache.commons.codec.digest.HmacUtils;
import org.springframework.util.Assert;

/**
 * A implementation of {@link SignCalculator} which uses HMAC to calculate
 * signature.
 *
 * @author Takuya Iwatsuka
 */
public class HmacSignCalculator extends AbstractSignCalculator {

	protected final String key;

	/**
	 * Specifies a secret key for calculate signature.
	 *
	 * @param key a secret key for calculate signature
	 */
	public HmacSignCalculator(String key) {
		Assert.hasLength(key);
		this.key = key;
	}

	@Override
	public String calculateSign(String source) {
		return HmacUtils.hmacSha256Hex(key, source);
	}

}
