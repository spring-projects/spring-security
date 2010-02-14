/**
 * Pre-authentication support for container-authenticated requests.
 * <p>
 * It is assumed that standard JEE security has been configured and Spring Security hooks into the
 * security methods exposed by {@code HttpServletRequest} to build {@code Authentication} object for the user.
 */
package org.springframework.security.web.authentication.preauth.j2ee;

