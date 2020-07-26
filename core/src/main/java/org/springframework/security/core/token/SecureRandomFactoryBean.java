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
package org.springframework.security.core.token;

import java.io.InputStream;
import java.security.SecureRandom;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.core.io.Resource;
import org.springframework.util.Assert;
import org.springframework.util.FileCopyUtils;

/**
 * Creates a {@link SecureRandom} instance.
 *
 * @author Ben Alex
 * @since 2.0.1
 */
public class SecureRandomFactoryBean implements FactoryBean<SecureRandom> {

	private String algorithm = "SHA1PRNG";

	private Resource seed;

	public SecureRandom getObject() throws Exception {
		SecureRandom rnd = SecureRandom.getInstance(this.algorithm);

		// Request the next bytes, thus eagerly incurring the expense of default
		// seeding and to prevent the see from replacing the entire state
		rnd.nextBytes(new byte[1]);

		if (this.seed != null) {
			// Seed specified, so use it
			byte[] seedBytes = FileCopyUtils.copyToByteArray(this.seed.getInputStream());
			rnd.setSeed(seedBytes);
		}

		return rnd;
	}

	public Class<SecureRandom> getObjectType() {
		return SecureRandom.class;
	}

	public boolean isSingleton() {
		return false;
	}

	/**
	 * Allows the Pseudo Random Number Generator (PRNG) algorithm to be nominated.
	 * Defaults to "SHA1PRNG".
	 * @param algorithm to use (mandatory)
	 */
	public void setAlgorithm(String algorithm) {
		Assert.hasText(algorithm, "Algorithm required");
		this.algorithm = algorithm;
	}

	/**
	 * Allows the user to specify a resource which will act as a seed for the
	 * {@link SecureRandom} instance. Specifically, the resource will be read into an
	 * {@link InputStream} and those bytes presented to the
	 * {@link SecureRandom#setSeed(byte[])} method. Note that this will simply supplement,
	 * rather than replace, the existing seed. As such, it is always safe to set a seed
	 * using this method (it never reduces randomness).
	 * @param seed to use, or <code>null</code> if no additional seeding is needed
	 */
	public void setSeed(Resource seed) {
		this.seed = seed;
	}

}
