package org.springframework.security.annotation;

import java.util.ArrayList;
import java.util.List;

import org.springframework.security.expression.annotation.PostFilter;
import org.springframework.security.expression.annotation.PreFilter;

public class ExpressionProtectedBusinessServiceImpl implements BusinessService {

    public void someAdminMethod() {
    }

    public int someOther(String s) {
        return 0;
    }

    public int someOther(int input) {
        return 0;
    }

    public void someUserAndAdminMethod() {
    }

    public void someUserMethod1() {
    }

    public void someUserMethod2() {
    }

    @PreFilter(filterTarget="someList", value="filterObject == name or filterObject == 'sam'")
    @PostFilter("filterObject == 'bob'")
    public List methodReturningAList(List someList) {
        return someList;
    }

    public List methodReturningAList(String userName, String arg2) {
        return new ArrayList();
    }

    @PreFilter(filterTarget="someArray", value="filterObject == name or filterObject == 'sam'")
    @PostFilter("filterObject == 'bob'")
    public Object[] methodReturningAnArray(Object[] someArray) {
        return someArray;
    }
}
