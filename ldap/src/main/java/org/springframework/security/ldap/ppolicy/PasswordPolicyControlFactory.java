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

package org.springframework.security.ldap.ppolicy;

import javax.naming.ldap.Control;
import javax.naming.ldap.ControlFactory;

/**
 * Transforms a control object to a PasswordPolicyResponseControl object, if appropriate.
 *
 * @author Stefan Zoerner
 * @author Luke Taylor
 */
public class PasswordPolicyControlFactory extends ControlFactory {

	/**
	 * Creates an instance of PasswordPolicyResponseControl if the passed control is a
	 * response control of this type. Attributes of the result are filled with the correct
	 * values (e.g. error code).
	 * @param ctl the control the check
	 * @return a response control of type PasswordPolicyResponseControl, or null
	 */
	public Control getControlInstance(Control ctl) {
		if (ctl.getID().equals(PasswordPolicyControl.OID)) {
			return new PasswordPolicyResponseControl(ctl.getEncodedValue());
		}

		return null;
	}

}
