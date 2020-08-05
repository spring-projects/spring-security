/*
 * Copyright 2002-2016 the original author or authors.
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
package org.springframework.security.ldap.ppolicy;

import javax.naming.ldap.Control;

import org.junit.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * @author Luke Taylor
 */
public class PasswordPolicyControlFactoryTests {

	@Test
	public void returnsNullForUnrecognisedOID() {
		PasswordPolicyControlFactory ctrlFactory = new PasswordPolicyControlFactory();
		Control wrongCtrl = mock(Control.class);

		when(wrongCtrl.getID()).thenReturn("wrongId");
		assertThat(ctrlFactory.getControlInstance(wrongCtrl)).isNull();
	}

	@Test
	public void returnsControlForCorrectOID() {
		PasswordPolicyControlFactory ctrlFactory = new PasswordPolicyControlFactory();
		Control control = mock(Control.class);

		when(control.getID()).thenReturn(PasswordPolicyControl.OID);
		when(control.getEncodedValue()).thenReturn(PasswordPolicyResponseControlTests.OPENLDAP_LOCKED_CTRL);
		Control result = ctrlFactory.getControlInstance(control);
		assertThat(result).isNotNull();
		assertThat(PasswordPolicyResponseControlTests.OPENLDAP_LOCKED_CTRL).isEqualTo(result.getEncodedValue());
	}

}
