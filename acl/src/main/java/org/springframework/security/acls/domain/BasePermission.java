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

import org.springframework.security.acls.model.Permission;


/**
 * A set of standard permissions.
 *
 * <p>
 * You may subclass this class to add additional permissions, or use this class as a guide
 * for creating your own permission classes.
 * </p>
 *
 * @author Ben Alex
 * @version $Id$
 */
public class BasePermission extends AbstractPermission {
    public static final Permission READ = new BasePermission(1 << 0, 'R'); // 1
    public static final Permission WRITE = new BasePermission(1 << 1, 'W'); // 2
    public static final Permission CREATE = new BasePermission(1 << 2, 'C'); // 4
    public static final Permission DELETE = new BasePermission(1 << 3, 'D'); // 8
    public static final Permission ADMINISTRATION = new BasePermission(1 << 4, 'A'); // 16

    protected static DefaultPermissionFactory defaultPermissionFactory = new DefaultPermissionFactory();

    protected BasePermission(int mask) {
       super(mask);
    }

    protected BasePermission(int mask, char code) {
        super(mask, code);
    }

//    public final static Permission buildFromMask(int mask) {
//        return defaultPermissionFactory.buildFromMask(mask);
//    }
//
//    public final static Permission[] buildFromMask(int[] masks) {
//        return defaultPermissionFactory.buildFromMask(masks);
//    }
//
//    public final static Permission buildFromName(String name) {
//        return defaultPermissionFactory.buildFromName(name);
//    }
//
//    public final static Permission[] buildFromName(String[] names) {
//        return defaultPermissionFactory.buildFromName(names);
//    }

}
