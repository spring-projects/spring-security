package org.springframework.security.annotation;

/**
 *
 * @author Joe Scalise
 */
public interface DepartmentService extends BusinessService {

    @Secured({"ROLE_USER"})
    Department someUserMethod3(Department dept);
}
