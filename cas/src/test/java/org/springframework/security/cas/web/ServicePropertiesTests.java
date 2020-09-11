/*
 * Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
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

package org.springframework.security.cas.web;

import org.junit.Test;

import org.springframework.security.cas.SamlServiceProperties;
import org.springframework.security.cas.ServiceProperties;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Tests {@link ServiceProperties}.
 *
 * @author Ben Alex
 */
public class ServicePropertiesTests {

	@Test
	public void detectsMissingService() throws Exception {
		ServiceProperties sp = new ServiceProperties();
		assertThatIllegalArgumentException().isThrownBy(sp::afterPropertiesSet);
	}

	@Test
	public void nullServiceWhenAuthenticateAllTokens() throws Exception {
		ServiceProperties sp = new ServiceProperties();
		sp.setAuthenticateAllArtifacts(true);
		assertThatIllegalArgumentException().isThrownBy(sp::afterPropertiesSet);
		sp.setAuthenticateAllArtifacts(false);
		assertThatIllegalArgumentException().isThrownBy(sp::afterPropertiesSet);
	}

	@Test
	public void testGettersSetters() throws Exception {
		ServiceProperties[] sps = { new ServiceProperties(), new SamlServiceProperties() };
		for (ServiceProperties sp : sps) {
			sp.setSendRenew(false);
			assertThat(sp.isSendRenew()).isFalse();
			sp.setSendRenew(true);
			assertThat(sp.isSendRenew()).isTrue();
			sp.setArtifactParameter("notticket");
			assertThat(sp.getArtifactParameter()).isEqualTo("notticket");
			sp.setServiceParameter("notservice");
			assertThat(sp.getServiceParameter()).isEqualTo("notservice");
			sp.setService("https://mycompany.com/service");
			assertThat(sp.getService()).isEqualTo("https://mycompany.com/service");
			sp.afterPropertiesSet();
		}
	}

}
