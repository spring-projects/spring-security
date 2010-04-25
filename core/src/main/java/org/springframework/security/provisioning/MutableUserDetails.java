package org.springframework.security.provisioning;

import org.springframework.security.core.userdetails.UserDetails;

/**
 *
 * @author Luke Taylor
 * @since 3.1
 */
interface MutableUserDetails extends UserDetails {

    void setPassword(String password);

}
