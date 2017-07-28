/*
 * Copyright 2012-2017 the original author or authors.
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
package org.springframework.security.oauth2.core.http;

import org.springframework.util.Assert;

/**
 * This class provides the capability for configuring the underlying HTTP client.
 *
 * <p>
 * To customize the configuration of the underlying HTTP client, create/configure
 * an instance of {@link HttpClientConfig} and register it with the <code>ApplicationContext</code>.
 *
 * <p>
 * For example:
 *
 * <pre>
 * &#064;Bean
 * public HttpClientConfig httpClientConfig() {
 *    HttpClientConfig httpClientConfig = new HttpClientConfig();
 *    httpClientConfig.setConnectTimeout(60000);
 *    httpClientConfig.setReadTimeout(60000);
 *    return httpClientConfig;
 * }
 * </pre>
 *
 * @author Joe Grandja
 * @since 5.0
 */
public class HttpClientConfig {
	public static final int DEFAULT_CONNECT_TIMEOUT = 30000;
	public static final int DEFAULT_READ_TIMEOUT = 30000;
	private int connectTimeout = DEFAULT_CONNECT_TIMEOUT;
	private int readTimeout = DEFAULT_READ_TIMEOUT;

	/**
	 * Returns the timeout in milliseconds until a connection is established.
	 *
	 * @return the connect timeout value in milliseconds
	 */
	public int getConnectTimeout() {
		return this.connectTimeout;
	}

	/**
	 * Sets the timeout in milliseconds until a connection is established.
	 * A timeout value of 0 implies the option is disabled (timeout of infinity).
	 *
	 * @param connectTimeout the connect timeout value in milliseconds
	 */
	public void setConnectTimeout(int connectTimeout) {
		Assert.isTrue(connectTimeout >= 0, "connectTimeout cannot be negative");
		this.connectTimeout = connectTimeout;
	}

	/**
	 * Returns the timeout in milliseconds for inactivity when reading from the <code>InputStream</code>.
	 *
	 * @return the read timeout value in milliseconds
	 */
	public int getReadTimeout() {
		return this.readTimeout;
	}

	/**
	 * Sets the timeout in milliseconds for inactivity when reading from the <code>InputStream</code>.
	 * A timeout value of 0 implies the option is disabled (timeout of infinity).
	 *
	 * @param readTimeout the read timeout value in milliseconds
	 */
	public void setReadTimeout(int readTimeout) {
		Assert.isTrue(readTimeout >= 0, "readTimeout cannot be negative");
		this.readTimeout = readTimeout;
	}

}
