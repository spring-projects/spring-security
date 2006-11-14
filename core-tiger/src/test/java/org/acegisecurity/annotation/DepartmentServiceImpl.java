package org.acegisecurity.annotation;

/**
 * @author Joe Scalise
 */
public class DepartmentServiceImpl extends BusinessServiceImpl <Department> implements DepartmentService {

    @Secured({"ROLE_ADMIN"})
    public Department someUserMethod3(final Department dept) {
        return super.someUserMethod3(dept);
    }
}
