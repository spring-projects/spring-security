/* Copyright 2004, 2005, 2006 Acegi Technology Pty Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.acegisecurity.runas;

import org.acegisecurity.Authentication;
import org.acegisecurity.ConfigAttribute;
import org.acegisecurity.ConfigAttributeDefinition;
import org.acegisecurity.RunAsManager;


/**
 * Implementation of a {@link RunAsManager} that does nothing.<p>This class should be used if you do not require
 * run-as authenticaiton replacement functionality.</p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class NullRunAsManager implements RunAsManager {
    //~ Methods ========================================================================================================

    public Authentication buildRunAs(Authentication authentication, Object object, ConfigAttributeDefinition config) {
        return null;
    }

    public boolean supports(ConfigAttribute attribute) {
        return false;
    }

    public boolean supports(Class clazz) {
        return true;
    }
}
