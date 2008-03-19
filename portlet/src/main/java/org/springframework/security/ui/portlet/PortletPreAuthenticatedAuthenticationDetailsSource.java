package org.springframework.security.ui.portlet;

import java.util.ArrayList;

import javax.portlet.PortletRequest;

import org.springframework.security.ui.preauth.j2ee.AbstractPreAuthenticatedAuthenticationDetailsSource;

public class PortletPreAuthenticatedAuthenticationDetailsSource extends AbstractPreAuthenticatedAuthenticationDetailsSource {
    
    public PortletPreAuthenticatedAuthenticationDetailsSource() {
         setClazz(PortletPreAuthenticatedAuthenticationDetails.class);
    }

    protected String[] getUserRoles(Object context, String[] mappableRoles) {
        ArrayList portletRoles = new ArrayList();

        for (int i = 0; i < mappableRoles.length; i++) {
            if (((PortletRequest)context).isUserInRole(mappableRoles[i])) {
                portletRoles.add(mappableRoles[i]);
            }
        }
        
        return (String[]) portletRoles.toArray(new String[portletRoles.size()]);
    }

}
