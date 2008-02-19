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

import org.springframework.security.acls.AclFormattingUtils;
import org.springframework.security.acls.Permission;

import org.springframework.util.Assert;

import java.lang.reflect.Field;

import java.util.HashMap;
import java.util.Map;


/**
 * A set of standard permissions.
 *
 * @author Ben Alex
 * @version $Id$
 */
public final class BasePermission implements Permission {
    //~ Static fields/initializers =====================================================================================

    public static final Permission READ = new BasePermission(1 << 0, 'R'); // 1
    public static final Permission WRITE = new BasePermission(1 << 1, 'W'); // 2
    public static final Permission CREATE = new BasePermission(1 << 2, 'C'); // 4
    public static final Permission DELETE = new BasePermission(1 << 3, 'D'); // 8
    public static final Permission ADMINISTRATION = new BasePermission(1 << 4, 'A'); // 16
    private static Map locallyDeclaredPermissionsByInteger = new HashMap();
    private static Map locallyDeclaredPermissionsByName = new HashMap();

    static {
        Field[] fields = BasePermission.class.getDeclaredFields();

        for (int i = 0; i < fields.length; i++) {
            try {
                Object fieldValue = fields[i].get(null);

                if (BasePermission.class.isAssignableFrom(fieldValue.getClass())) {
                    // Found a BasePermission static field
                    BasePermission perm = (BasePermission) fieldValue;
                    locallyDeclaredPermissionsByInteger.put(new Integer(perm.getMask()), perm);
                    locallyDeclaredPermissionsByName.put(fields[i].getName(), perm);
                }
            } catch (Exception ignore) {}
        }
    }

    //~ Instance fields ================================================================================================

    private char code;
    private int mask;

    //~ Constructors ===================================================================================================

    private BasePermission(int mask, char code) {
        this.mask = mask;
        this.code = code;
    }

    //~ Methods ========================================================================================================

    /**
     * Dynamically creates a <code>CumulativePermission</code> or <code>BasePermission</code> representing the
     * active bits in the passed mask.
     *
     * @param mask to build
     *
     * @return a Permission representing the requested object
     */
    public static Permission buildFromMask(int mask) {
        if (locallyDeclaredPermissionsByInteger.containsKey(new Integer(mask))) {
            // The requested mask has an exactly match against a statically-defined BasePermission, so return it
            return (Permission) locallyDeclaredPermissionsByInteger.get(new Integer(mask));
        }

        // To get this far, we have to use a CumulativePermission
        CumulativePermission permission = new CumulativePermission();

        for (int i = 0; i < 32; i++) {
            int permissionToCheck = 1 << i;

            if ((mask & permissionToCheck) == permissionToCheck) {
                Permission p = (Permission) locallyDeclaredPermissionsByInteger.get(new Integer(permissionToCheck));
                Assert.state(p != null,
                    "Mask " + permissionToCheck + " does not have a corresponding static BasePermission");
                permission.set(p);
            }
        }

        return permission;
    }

    public static Permission[] buildFromMask(int[] masks) {
        if ((masks == null) || (masks.length == 0)) {
            return new Permission[0];
        }

        Permission[] permissions = new Permission[masks.length];

        for (int i = 0; i < masks.length; i++) {
            permissions[i] = buildFromMask(masks[i]);
        }

        return permissions;
    }

    public static Permission buildFromName(String name) {
        Assert.isTrue(locallyDeclaredPermissionsByName.containsKey(name), "Unknown permission '" + name + "'");

        return (Permission) locallyDeclaredPermissionsByName.get(name);
    }

    public static Permission[] buildFromName(String[] names) {
        if ((names == null) || (names.length == 0)) {
            return new Permission[0];
        }

        Permission[] permissions = new Permission[names.length];

        for (int i = 0; i < names.length; i++) {
            permissions[i] = buildFromName(names[i]);
        }

        return permissions;
    }

    public boolean equals(Object arg0) {
        if (arg0 == null) {
            return false;
        }

        if (!(arg0 instanceof Permission)) {
            return false;
        }

        Permission rhs = (Permission) arg0;

        return (this.mask == rhs.getMask());
    }

    public int getMask() {
        return mask;
    }

    public String getPattern() {
        return AclFormattingUtils.printBinary(mask, code);
    }

    public String toString() {
        return "BasePermission[" + getPattern() + "=" + mask + "]";
    }

	public int hashCode() {
		return this.mask;
	}
}
