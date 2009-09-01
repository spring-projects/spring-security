package org.springframework.security.cas.userdetails;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.GrantedAuthorityImpl;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.util.Assert;
import org.jasig.cas.client.validation.Assertion;

import java.util.List;
import java.util.ArrayList;

/**
 * Populates the {@link org.springframework.security.core.GrantedAuthority}s for a user by reading a list of attributes that were returned as
 * part of the CAS response.  Each attribute is read and each value of the attribute is turned into a GrantedAuthority.  If the attribute has no
 * value then its not added.
 *
 * @author Scott Battaglia
 * @version $Revision$ $Date$
 * @since 3.0
 */
public final class GrantedAuthorityFromAssertionAttributesUserDetailsService extends AbstractCasAssertionUserDetailsService implements InitializingBean {

    private String[] attributes;

    @Override
    protected UserDetails loadUserDetails(final Assertion assertion) {
        final List<GrantedAuthority> grantedAuthorities = new ArrayList<GrantedAuthority>();

        for (final String attribute : this.attributes) {
            final Object attributes = assertion.getPrincipal().getAttributes().get(attribute);

            if (attributes == null) {
                continue;
            }

            if (attributes instanceof List) {
                final List list = (List) attributes;

                for (final Object o : list) {
                    grantedAuthorities.add(new GrantedAuthorityImpl(o.toString()));
                }

            } else {
                grantedAuthorities.add(new GrantedAuthorityImpl(attributes.toString()));
            }

        }

        return new User(assertion.getPrincipal().getName(), null, true, true, true, true, grantedAuthorities);
    }

    public void afterPropertiesSet() throws Exception {
        Assert.isTrue(attributes != null && attributes.length > 0, "At least one attribute is required to retrieve roles from.");
    }
}
