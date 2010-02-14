/**
 * Strategy interface and implementations for handling session-related behaviour for a newly authenticated user.
 * <p>
 * Comes with support for:
 * <ul>
 * <li>Protection against session-fixation attacks</li>
 * <li>Controlling the number of sessions an authenticated user can have open</li>
 * </ul>
 */
package org.springframework.security.web.authentication.session;

