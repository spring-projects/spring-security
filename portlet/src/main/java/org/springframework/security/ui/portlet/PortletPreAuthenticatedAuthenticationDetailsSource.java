package org.springframework.security.ui.portlet;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Set;

import javax.portlet.PortletRequest;

import org.springframework.security.web.authentication.preauth.j2ee.AbstractPreAuthenticatedAuthenticationDetailsSource;

public class PortletPreAuthenticatedAuthenticationDetailsSource extends AbstractPreAuthenticatedAuthenticationDetailsSource {

    public PortletPreAuthenticatedAuthenticationDetailsSource() {
         setClazz(PortletPreAuthenticatedAuthenticationDetails.class);
    }

    protected Collection<String> getUserRoles(Object context, Set<String> mappableRoles) {
        ArrayList<String> portletRoles = new ArrayList<String>();

        for (String role : mappableRoles) {
            if (((PortletRequest)context).isUserInRole(role)) {
                portletRoles.add(role);
            }
        }
        portletRoles.trimToSize();

        return portletRoles;
    }

}
