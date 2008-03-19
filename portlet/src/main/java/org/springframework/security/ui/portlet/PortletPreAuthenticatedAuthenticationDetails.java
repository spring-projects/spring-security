package org.springframework.security.ui.portlet;

import java.util.Arrays;

import javax.portlet.PortletRequest;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.MutableGrantedAuthoritiesContainer;
import org.springframework.util.Assert;

public class PortletPreAuthenticatedAuthenticationDetails extends PortletAuthenticationDetails implements MutableGrantedAuthoritiesContainer {
    
    private GrantedAuthority[] preAuthenticatedGrantedAuthorities = null;
    
    public PortletPreAuthenticatedAuthenticationDetails(PortletRequest request) {
        super(request);
    }
    
    public GrantedAuthority[] getGrantedAuthorities() {
        Assert.notNull(preAuthenticatedGrantedAuthorities, "Pre-authenticated granted authorities have not been set");
        GrantedAuthority[] result = new GrantedAuthority[preAuthenticatedGrantedAuthorities.length];
        System.arraycopy(preAuthenticatedGrantedAuthorities, 0, result, 0, result.length);
        return result;
    }

    public void setGrantedAuthorities(GrantedAuthority[] authorities) {
        this.preAuthenticatedGrantedAuthorities = new GrantedAuthority[authorities.length];
        System.arraycopy(authorities, 0, preAuthenticatedGrantedAuthorities, 0, preAuthenticatedGrantedAuthorities.length);
    }
    
    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString() + "; ");
        sb.append("preAuthenticatedGrantedAuthorities: " + Arrays.asList(preAuthenticatedGrantedAuthorities));
        return sb.toString();
    }
}
