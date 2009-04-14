package org.springframework.security.web.authentication.preauth.j2ee;

import org.springframework.security.web.authentication.preauth.PreAuthenticatedGrantedAuthoritiesWebAuthenticationDetails;
import org.springframework.security.core.authoritymapping.SimpleAttributes2GrantedAuthoritiesMapper;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

import javax.servlet.http.HttpServletRequest;

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
    protected Collection<String> getUserRoles(Object context, Set<String> mappableRoles) {
        ArrayList<String> j2eeUserRolesList = new ArrayList<String>();

        for (String role : mappableRoles) {
            if (((HttpServletRequest)context).isUserInRole(role)) {
                j2eeUserRolesList.add(role);
            }
        }

        return j2eeUserRolesList;
    }
}
