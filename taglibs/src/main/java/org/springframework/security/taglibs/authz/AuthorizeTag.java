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

package org.springframework.security.taglibs.authz;

import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.Set;

import javax.servlet.jsp.JspException;
import javax.servlet.jsp.tagext.Tag;
import javax.servlet.jsp.tagext.TagSupport;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.util.ExpressionEvaluationUtils;


/**
 * An implementation of {@link javax.servlet.jsp.tagext.Tag} that allows it's body through if some authorizations
 * are granted to the request's principal.
 *
 * @author Francois Beausoleil
 * @version $Id$
 */
public class AuthorizeTag extends TagSupport {
    //~ Instance fields ================================================================================================

    private String ifAllGranted = "";
    private String ifAnyGranted = "";
    private String ifNotGranted = "";

    //~ Methods ========================================================================================================

    private Set<String> authoritiesToRoles(Collection<GrantedAuthority> c) {
        Set<String> target = new HashSet<String>();

        for (GrantedAuthority authority : c) {
            if (null == authority.getAuthority()) {
                throw new IllegalArgumentException(
                    "Cannot process GrantedAuthority objects which return null from getAuthority() - attempting to process "
                    + authority.toString());
            }

            target.add(authority.getAuthority());
        }

        return target;
    }

    public int doStartTag() throws JspException {
        if (((null == ifAllGranted) || "".equals(ifAllGranted)) && ((null == ifAnyGranted) || "".equals(ifAnyGranted))
            && ((null == ifNotGranted) || "".equals(ifNotGranted))) {
            return Tag.SKIP_BODY;
        }

        final Collection<GrantedAuthority> granted = getPrincipalAuthorities();

        final String evaledIfNotGranted = ExpressionEvaluationUtils.evaluateString("ifNotGranted", ifNotGranted,
                pageContext);

        if ((null != evaledIfNotGranted) && !"".equals(evaledIfNotGranted)) {
            Set<GrantedAuthority> grantedCopy = retainAll(granted, parseAuthoritiesString(evaledIfNotGranted));

            if (!grantedCopy.isEmpty()) {
                return Tag.SKIP_BODY;
            }
        }

        final String evaledIfAllGranted = ExpressionEvaluationUtils.evaluateString("ifAllGranted", ifAllGranted,
                pageContext);

        if ((null != evaledIfAllGranted) && !"".equals(evaledIfAllGranted)) {
            if (!granted.containsAll(parseAuthoritiesString(evaledIfAllGranted))) {
                return Tag.SKIP_BODY;
            }
        }

        final String evaledIfAnyGranted = ExpressionEvaluationUtils.evaluateString("ifAnyGranted", ifAnyGranted,
                pageContext);

        if ((null != evaledIfAnyGranted) && !"".equals(evaledIfAnyGranted)) {
            Set<GrantedAuthority> grantedCopy = retainAll(granted, parseAuthoritiesString(evaledIfAnyGranted));

            if (grantedCopy.isEmpty()) {
                return Tag.SKIP_BODY;
            }
        }

        return Tag.EVAL_BODY_INCLUDE;
    }

    public String getIfAllGranted() {
        return ifAllGranted;
    }

    public String getIfAnyGranted() {
        return ifAnyGranted;
    }

    public String getIfNotGranted() {
        return ifNotGranted;
    }

    private Collection<GrantedAuthority> getPrincipalAuthorities() {
        Authentication currentUser = SecurityContextHolder.getContext().getAuthentication();

        if (null == currentUser) {
            return Collections.emptyList();
        }

        if ((null == currentUser.getAuthorities())) {
            return Collections.emptyList();
        }

        return currentUser.getAuthorities();
    }

    private Set<GrantedAuthority> parseAuthoritiesString(String authorizationsString) {
        final Set<GrantedAuthority> requiredAuthorities = new HashSet<GrantedAuthority>();
        requiredAuthorities.addAll(AuthorityUtils.commaSeparatedStringToAuthorityList(authorizationsString));

        return requiredAuthorities;
    }

    /**
     * Find the common authorities between the current authentication's {@link GrantedAuthority} and the ones
     * that have been specified in the tag's ifAny, ifNot or ifAllGranted attributes.<p>We need to manually
     * iterate over both collections, because the granted authorities might not implement {@link
     * Object#equals(Object)} and {@link Object#hashCode()} in the same way as {@link GrantedAuthorityImpl}, thereby
     * invalidating {@link Collection#retainAll(java.util.Collection)} results.</p>
     * <p>
     * <strong>CAVEAT</strong>:  This method <strong>will not</strong> work if the granted authorities
     * returns a <code>null</code> string as the return value of {@link GrantedAuthority#getAuthority()}.
     * </p>
     *
     * @param granted The authorities granted by the authentication. May be any implementation of {@link
     *        GrantedAuthority} that does <strong>not</strong> return <code>null</code> from {@link
     *        GrantedAuthority#getAuthority()}.
     * @param required A {@link Set} of {@link GrantedAuthorityImpl}s that have been built using ifAny, ifAll or
     *        ifNotGranted.
     *
     * @return A set containing only the common authorities between <var>granted</var> and <var>required</var>.
     *
     */
    private Set<GrantedAuthority> retainAll(final Collection<GrantedAuthority> granted, final Set<GrantedAuthority> required) {
        Set<String> grantedRoles = authoritiesToRoles(granted);
        Set<String> requiredRoles = authoritiesToRoles(required);
        grantedRoles.retainAll(requiredRoles);

        return rolesToAuthorities(grantedRoles, granted);
    }

    private Set<GrantedAuthority> rolesToAuthorities(Set<String> grantedRoles, Collection<GrantedAuthority> granted) {
        Set<GrantedAuthority> target = new HashSet<GrantedAuthority>();

        for (String role : grantedRoles) {
            for (GrantedAuthority authority : granted) {
                if (authority.getAuthority().equals(role)) {
                    target.add(authority);

                    break;
                }
            }
        }

        return target;
    }

    public void setIfAllGranted(String ifAllGranted) throws JspException {
        this.ifAllGranted = ifAllGranted;
    }

    public void setIfAnyGranted(String ifAnyGranted) throws JspException {
        this.ifAnyGranted = ifAnyGranted;
    }

    public void setIfNotGranted(String ifNotGranted) throws JspException {
        this.ifNotGranted = ifNotGranted;
    }
}
