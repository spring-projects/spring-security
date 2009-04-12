package org.springframework.security.access.annotation;

import org.springframework.security.access.annotation.Secured;

/**
 *
 * @author Joe Scalise
 */
public interface DepartmentService extends BusinessService {

    @Secured({"ROLE_USER"})
    Department someUserMethod3(Department dept);
}
