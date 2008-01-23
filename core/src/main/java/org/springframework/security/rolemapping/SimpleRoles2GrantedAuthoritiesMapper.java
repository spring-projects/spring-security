package org.springframework.security.rolemapping;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.GrantedAuthorityImpl;

import java.util.Locale;

import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;

/**
 * <p>
 * This class implements the Roles2GrantedAuthoritiesMapper interface by doing a
 * one-on-one mapping from roles to Acegi GrantedAuthorities. Optionally a
 * prefix can be added, and the role name can be converted to upper or lower
 * case.
 * <p>
 * By default, the role is prefixed with "ROLE_" unless it already starts with
 * "ROLE_", and no case conversion is done.
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class SimpleRoles2GrantedAuthoritiesMapper implements Roles2GrantedAuthoritiesMapper, InitializingBean {
    private String rolePrefix = "ROLE_";

    private boolean convertRoleToUpperCase = false;

    private boolean convertRoleToLowerCase = false;

    private boolean addPrefixIfAlreadyExisting = false;

    /**
     * Check whether all properties have been set to correct values.
     */
    public void afterPropertiesSet() throws Exception {
        Assert.isTrue(!(isConvertRoleToUpperCase() && isConvertRoleToLowerCase()),
                "Either convertRoleToUpperCase or convertRoleToLowerCase can be set to true, but not both");
    }

    /**
     * Map the given list of roles one-on-one to Acegi GrantedAuthorities.
     */
    public GrantedAuthority[] getGrantedAuthorities(String[] roles) {
        GrantedAuthority[] result = new GrantedAuthority[roles.length];
        for (int i = 0; i < roles.length; i++) {
            result[i] = getGrantedAuthority(roles[i]);
        }
        return result;
    }

    /**
     * Map the given role ono-on-one to an Acegi GrantedAuthority, optionally
     * doing case conversion and/or adding a prefix.
     *
     * @param role
     *            The role for which to get a GrantedAuthority
     * @return GrantedAuthority representing the given role.
     */
    private GrantedAuthority getGrantedAuthority(String role) {
        if (isConvertRoleToLowerCase()) {
            role = role.toLowerCase(Locale.getDefault());
        } else if (isConvertRoleToUpperCase()) {
            role = role.toUpperCase(Locale.getDefault());
        }
        if (isAddPrefixIfAlreadyExisting() || !role.startsWith(getRolePrefix())) {
            return new GrantedAuthorityImpl(getRolePrefix() + role);
        } else {
            return new GrantedAuthorityImpl(role);
        }
    }

    private boolean isConvertRoleToLowerCase() {
        return convertRoleToLowerCase;
    }

    public void setConvertRoleToLowerCase(boolean b) {
        convertRoleToLowerCase = b;
    }

    private boolean isConvertRoleToUpperCase() {
        return convertRoleToUpperCase;
    }

    public void setConvertRoleToUpperCase(boolean b) {
        convertRoleToUpperCase = b;
    }

    private String getRolePrefix() {
        return rolePrefix == null ? "" : rolePrefix;
    }

    public void setRolePrefix(String string) {
        rolePrefix = string;
    }

    private boolean isAddPrefixIfAlreadyExisting() {
        return addPrefixIfAlreadyExisting;
    }

    public void setAddPrefixIfAlreadyExisting(boolean b) {
        addPrefixIfAlreadyExisting = b;
    }

}
