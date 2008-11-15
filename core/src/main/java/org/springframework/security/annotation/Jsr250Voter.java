package org.springframework.security.annotation;

import org.springframework.security.GrantedAuthority;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.Authentication;
import org.springframework.security.vote.AccessDecisionVoter;

import java.util.Iterator;
import java.util.List;

/**
 * Voter on JSR-250 configuration attributes.
 *
 * @author Ryan Heaton
 * @since 2.0
 */
public class Jsr250Voter implements AccessDecisionVoter {

    /**
     * The specified config attribute is supported if its an instance of a {@link Jsr250SecurityConfig}.
     *
     * @param configAttribute The config attribute.
     * @return whether the config attribute is supported.
     */
    public boolean supports(ConfigAttribute configAttribute) {
        return configAttribute instanceof Jsr250SecurityConfig;
    }

    /**
     * All classes are supported.
     *
     * @param clazz the class.
     * @return true
     */
    public boolean supports(Class<?> clazz) {
        return true;
    }

    /**
     * Votes according to JSR 250.
     *
     * @param authentication The authentication object.
     * @param object         The access object.
     * @param definition     The configuration definition.
     * @return The vote.
     */
    public int vote(Authentication authentication, Object object, List<ConfigAttribute> definition) {
        int result = ACCESS_ABSTAIN;
        Iterator iter = definition.iterator();

        while (iter.hasNext()) {
            ConfigAttribute attribute = (ConfigAttribute) iter.next();

            if (Jsr250SecurityConfig.PERMIT_ALL_ATTRIBUTE.equals(attribute)) {
                return ACCESS_GRANTED;
            }

            if (Jsr250SecurityConfig.DENY_ALL_ATTRIBUTE.equals(attribute)) {
                return ACCESS_DENIED;
            }

            if (supports(attribute)) {
                result = ACCESS_DENIED;

                // Attempt to find a matching granted authority
                for (GrantedAuthority authority : authentication.getAuthorities()) {
                    if (attribute.getAttribute().equals(authority.getAuthority())) {
                        return ACCESS_GRANTED;
                    }
                }
            }
        }

        return result;
    }
}

