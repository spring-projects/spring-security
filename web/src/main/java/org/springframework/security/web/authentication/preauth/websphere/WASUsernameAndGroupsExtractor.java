package org.springframework.security.web.authentication.preauth.websphere;

import java.util.List;

/**
 * Provides indirection between classes using websphere and the actual container interaction,
 * allowing for easier unit testing.
 * <p>
 * Only for internal use.
 *
 * @author Luke Taylor
 * @version $Id$
 * @since 3.0.0
 */
interface WASUsernameAndGroupsExtractor {

    List<String> getGroupsForCurrentUser();

    String getCurrentUserName();
}
