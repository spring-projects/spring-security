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

package org.springframework.security.kerberos.test;

import java.io.File;
import java.util.Properties;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;

/**
 * KerberosSecurityTestcase provides a base class for using MiniKdc with other testcases.
 * KerberosSecurityTestcase starts the MiniKdc (@BeforeEach) before running tests, and
 * stop the MiniKdc (@AfterEach) after the testcases, using default settings (working dir
 * and kdc configurations).
 * <p>
 * Users can directly inherit this class and implement their own test functions using the
 * default settings, or override functions getTestDir() and createMiniKdcConf() to provide
 * new settings.
 *
 */
public class KerberosSecurityTestcase {

	private MiniKdc kdc;

	private File workDir;

	private Properties conf;

	@BeforeEach
	public void startMiniKdc() throws Exception {
		createTestDir();
		createMiniKdcConf();

		this.kdc = new MiniKdc(this.conf, this.workDir);
		this.kdc.start();
	}

	/**
	 * Create a working directory, it should be the build directory. Under this directory
	 * an ApacheDS working directory will be created, this directory will be deleted when
	 * the MiniKdc stops.
	 */
	public void createTestDir() {
		this.workDir = new File(System.getProperty("test.dir", "target"));
	}

	/**
	 * Create a Kdc configuration
	 */
	public void createMiniKdcConf() {
		this.conf = MiniKdc.createConf();
	}

	@AfterEach
	public void stopMiniKdc() {
		if (this.kdc != null) {
			this.kdc.stop();
		}
	}

	public MiniKdc getKdc() {
		return this.kdc;
	}

	public File getWorkDir() {
		return this.workDir;
	}

	public Properties getConf() {
		return this.conf;
	}

}
