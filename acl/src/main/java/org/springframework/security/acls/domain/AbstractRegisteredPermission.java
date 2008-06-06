package org.springframework.security.acls.domain;

import org.springframework.security.acls.Permission;

/**
 * Provides an abstract base for standard {@link Permission} instances that wish to offer static convenience
 * methods to callers via delegation to {@link DefaultPermissionFactory}.
 * 
 * @author Ben Alex
 * @since 2.0.3
 *
 */
public abstract class AbstractRegisteredPermission extends AbstractPermission {
	protected static DefaultPermissionFactory defaultPermissionFactory = new DefaultPermissionFactory();

    protected AbstractRegisteredPermission(int mask, char code) {
    	super(mask, code);
    }
	
    protected final static void registerPermissionsFor(Class subClass) {
    	defaultPermissionFactory.registerPublicPermissions(subClass);
    }
    
    public final static Permission buildFromMask(int mask) {
        return defaultPermissionFactory.buildFromMask(mask);
    }

    public final static Permission[] buildFromMask(int[] masks) {
        return defaultPermissionFactory.buildFromMask(masks);
    }

    public final static Permission buildFromName(String name) {
    	return defaultPermissionFactory.buildFromName(name);
    }

    public final static Permission[] buildFromName(String[] names) {
        return defaultPermissionFactory.buildFromName(names);
    }
}
