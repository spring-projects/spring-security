package org.springframework.security.ui.portlet;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.portlet.PortletRequest;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.MutableGrantedAuthoritiesContainer;
import org.springframework.util.Assert;

public class PortletPreAuthenticatedAuthenticationDetails extends PortletAuthenticationDetails implements MutableGrantedAuthoritiesContainer {

    private List<GrantedAuthority> preAuthenticatedGrantedAuthorities = null;

    public PortletPreAuthenticatedAuthenticationDetails(PortletRequest request) {
        super(request);
    }

    public List<GrantedAuthority> getGrantedAuthorities() {
        Assert.notNull(preAuthenticatedGrantedAuthorities, "Pre-authenticated granted authorities have not been set");
        return preAuthenticatedGrantedAuthorities;
    }

    public void setGrantedAuthorities(List<GrantedAuthority> authorities) {
        this.preAuthenticatedGrantedAuthorities = Collections.unmodifiableList(authorities);
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append(super.toString() + "; ");
        sb.append("preAuthenticatedGrantedAuthorities: " + Arrays.asList(preAuthenticatedGrantedAuthorities));
        return sb.toString();
    }
}
