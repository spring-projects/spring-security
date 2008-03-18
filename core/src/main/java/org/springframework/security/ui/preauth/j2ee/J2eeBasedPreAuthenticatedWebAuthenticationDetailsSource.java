package org.springframework.security.ui.preauth.j2ee;

import org.springframework.security.ui.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.security.authoritymapping.SimpleAttributes2GrantedAuthoritiesMapper;

import java.util.ArrayList;

import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.InitializingBean;

/**
 * Implementation of AuthenticationDetailsSource which converts the user's J2EE roles (as obtained by calling
 * {@link HttpServletRequest#isUserInRole(String)}) into GrantedAuthoritys and stores these in the authentication
 * details object (. 
 *
 * @author Ruud Senden
 * @since 2.0
 */
public class J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource extends AbstractPreAuthenticatedAuthenticationDetailsSource {
    /**
     * Public constructor which overrides the default AuthenticationDetails
     * class to be used.
     */
    public J2eeBasedPreAuthenticatedWebAuthenticationDetailsSource() {
        super.setClazz(PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails.class);
        
        j2eeUserRoles2GrantedAuthoritiesMapper = new SimpleAttributes2GrantedAuthoritiesMapper();
    }

    /**
     * Obtains the list of user roles based on the current user's J2EE roles.
     *
     * @param request The request against which <tt>isUserInRole</tt> will be called for each role name
     *                returned by the MappableAttributesRetriever. 
     * @return GrantedAuthority[] mapped from the user's J2EE roles.
     */
    protected String[] getUserRoles(Object context, String[] mappableRoles) {
        ArrayList j2eeUserRolesList = new ArrayList();

        for (int i = 0; i < mappableRoles.length; i++) {
            if (((HttpServletRequest)context).isUserInRole(mappableRoles[i])) {
                j2eeUserRolesList.add(mappableRoles[i]);
            }
        }
        
        return (String[]) j2eeUserRolesList.toArray(new String[j2eeUserRolesList.size()]);
    }
}
