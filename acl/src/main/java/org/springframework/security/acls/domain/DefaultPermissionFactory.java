package org.springframework.security.acls.domain;

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.acls.Permission;
import org.springframework.security.acls.jdbc.LookupStrategy;
import org.springframework.util.Assert;

/**
 * Default implementation of {@link PermissionFactory}.
 * 
 * <p>
 * Generally this class will be used by a {@link Permission} instance, as opposed to being dependency
 * injected into a {@link LookupStrategy} or similar. Nevertheless, the latter mode of operation is
 * fully supported (in which case your {@link Permission} implementations probably should extend
 * {@link AbstractPermission} instead of {@link AbstractRegisteredPermission}).
 * </p>
 * 
 * @author Ben Alex
 * @since 2.0.3
 *
 */
public class DefaultPermissionFactory implements PermissionFactory {
    private Map registeredPermissionsByInteger = new HashMap();
    private Map registeredPermissionsByName = new HashMap();

    /**
     * Permit registration of a {@link DefaultPermissionFactory} class. The class must provide
     * public static fields of type {@link Permission} to represent the possible permissions.
     * 
     * @param clazz a {@link Permission} class with public static fields to register
     */
    public void registerPublicPermissions(Class clazz) {
        Assert.notNull(clazz, "Class required");
        Assert.isAssignable(Permission.class, clazz);
        
        Field[] fields = clazz.getFields();

        for (int i = 0; i < fields.length; i++) {
            try {
                Object fieldValue = fields[i].get(null);

                if (Permission.class.isAssignableFrom(fieldValue.getClass())) {
                    // Found a Permission static field
                    Permission perm = (Permission) fieldValue;
                    String permissionName = fields[i].getName();
                    
                    registerPermission(perm, permissionName);
                }
            } catch (Exception ignore) {}
        }
    }

    public void registerPermission(Permission perm, String permissionName) {
        Assert.notNull(perm, "Permission required");
        Assert.hasText(permissionName, "Permission name required");
        
        Integer mask = new Integer(perm.getMask());

        // Ensure no existing Permission uses this integer or code
        Assert.isTrue(!registeredPermissionsByInteger.containsKey(mask), "An existing Permission already provides mask " + mask);
        Assert.isTrue(!registeredPermissionsByName.containsKey(permissionName), "An existing Permission already provides name '" + permissionName + "'");
        
        // Register the new Permission
        registeredPermissionsByInteger.put(mask, perm);
        registeredPermissionsByName.put(permissionName, perm);
    }
    
    public Permission buildFromMask(int mask) {
        if (registeredPermissionsByInteger.containsKey(new Integer(mask))) {
            // The requested mask has an exactly match against a statically-defined Permission, so return it
            return (Permission) registeredPermissionsByInteger.get(new Integer(mask));
        }

        // To get this far, we have to use a CumulativePermission
        CumulativePermission permission = new CumulativePermission();

        for (int i = 0; i < 32; i++) {
            int permissionToCheck = 1 << i;

            if ((mask & permissionToCheck) == permissionToCheck) {
                Permission p = (Permission) registeredPermissionsByInteger.get(new Integer(permissionToCheck));
                Assert.state(p != null, "Mask " + permissionToCheck + " does not have a corresponding static Permission");
                permission.set(p);
            }
        }

        return permission;
    }

    public Permission[] buildFromMask(int[] masks) {
        if ((masks == null) || (masks.length == 0)) {
            return new Permission[0];
        }

        Permission[] permissions = new Permission[masks.length];

        for (int i = 0; i < masks.length; i++) {
            permissions[i] = buildFromMask(masks[i]);
        }

        return permissions;
    }

    public Permission buildFromName(String name) {
        Assert.isTrue(registeredPermissionsByName.containsKey(name), "Unknown permission '" + name + "'");

        return (Permission) registeredPermissionsByName.get(name);
    }

    public Permission[] buildFromName(String[] names) {
        if ((names == null) || (names.length == 0)) {
            return new Permission[0];
        }

        Permission[] permissions = new Permission[names.length];

        for (int i = 0; i < names.length; i++) {
            permissions[i] = buildFromName(names[i]);
        }

        return permissions;
    }
    
}
