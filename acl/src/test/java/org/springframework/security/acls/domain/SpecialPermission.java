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
package org.springframework.security.acls.domain;

import org.springframework.security.acls.Permission;


/**
 * A test permission.
 * 
 * @author Ben Alex
 * @version $Id$
 */
public class SpecialPermission extends BasePermission {
    public static final Permission ENTER = new SpecialPermission(1 << 5, 'E'); // 32
    
    /**
     * Registers the public static permissions defined on this class. This is mandatory so
     * that the static methods will operate correctly.
     */
    static {
    	registerPermissionsFor(SpecialPermission.class);
    }

    protected SpecialPermission(int mask, char code) {
    	super(mask, code);
    }
}
