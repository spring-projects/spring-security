package org.springframework.security.expression.method;

import static org.junit.Assert.*;

import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.ConfigAttribute;
import org.springframework.security.expression.annotation.PostAuthorize;
import org.springframework.security.expression.annotation.PostFilter;
import org.springframework.security.expression.annotation.PreAuthorize;
import org.springframework.security.expression.annotation.PreFilter;
import org.springframework.security.expression.method.ExpressionAnnotationMethodDefinitionSource;
import org.springframework.security.expression.method.PostInvocationExpressionAttribute;
import org.springframework.security.expression.method.PreInvocationExpressionAttribute;
import org.springframework.security.intercept.method.MockMethodInvocation;


public class ExpressionAnnotationMethodDefinitionSourceTests {
    private ExpressionAnnotationMethodDefinitionSource mds = new ExpressionAnnotationMethodDefinitionSource();

    private MockMethodInvocation voidImpl1;
    private MockMethodInvocation voidImpl2;
    private MockMethodInvocation voidImpl3;
    private MockMethodInvocation listImpl1;
    private MockMethodInvocation notherListImpl1;
    private MockMethodInvocation notherListImpl2;

    @Before
    public void setUpData() throws Exception {
        voidImpl1 = new MockMethodInvocation(new ReturnVoidImpl1(), ReturnVoid.class, "doSomething", List.class);
        voidImpl2 = new MockMethodInvocation(new ReturnVoidImpl2(), ReturnVoid.class, "doSomething", List.class);
        voidImpl3 = new MockMethodInvocation(new ReturnVoidImpl3(), ReturnVoid.class, "doSomething", List.class);
        listImpl1 = new MockMethodInvocation(new ReturnAListImpl1(), ReturnAList.class, "doSomething", List.class);
        notherListImpl1 = new MockMethodInvocation(new ReturnAnotherListImpl1(), ReturnAnotherList.class, "doSomething", List.class);
        notherListImpl2 = new MockMethodInvocation(new ReturnAnotherListImpl2(), ReturnAnotherList.class, "doSomething", List.class);
    }

    @Test
    public void classLevelPreAnnotationIsPickedUpWhenNoMethodLevelExists() throws Exception {
        List<ConfigAttribute> attrs = mds.getAttributes(voidImpl1);

        assertEquals(1, attrs.size());
        assertTrue(attrs.get(0) instanceof PreInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs.get(0);
        assertNotNull(pre.getAuthorizeExpression());
        assertEquals("someExpression", pre.getAuthorizeExpression().getExpressionString());
        assertNull(pre.getFilterExpression());
    }

    @Test
    public void mixedClassAndMethodPreAnnotationsAreBothIncluded() {
        List<ConfigAttribute> attrs = mds.getAttributes(voidImpl2);

        assertEquals(1, attrs.size());
        assertTrue(attrs.get(0) instanceof PreInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute)attrs.get(0);
        assertEquals("someExpression", pre.getAuthorizeExpression().getExpressionString());
        assertNotNull(pre.getFilterExpression());
        assertEquals("somePreFilterExpression", pre.getFilterExpression().getExpressionString());
    }

    @Test
    public void methodWithPreFilterOnlyIsAllowed() {
        List<ConfigAttribute> attrs = mds.getAttributes(voidImpl3);

        assertEquals(1, attrs.size());
        assertTrue(attrs.get(0) instanceof PreInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute)attrs.get(0);
        assertEquals("permitAll", pre.getAuthorizeExpression().getExpressionString());
        assertNotNull(pre.getFilterExpression());
        assertEquals("somePreFilterExpression", pre.getFilterExpression().getExpressionString());
    }

    @Test
    public void methodWithPostFilterOnlyIsAllowed() {
        List<ConfigAttribute> attrs = mds.getAttributes(listImpl1);

        assertEquals(2, attrs.size());
        assertTrue(attrs.get(0) instanceof PreInvocationExpressionAttribute);
        assertTrue(attrs.get(1) instanceof PostInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute)attrs.get(0);
        PostInvocationExpressionAttribute post = (PostInvocationExpressionAttribute)attrs.get(1);
        assertEquals("permitAll", pre.getAuthorizeExpression().getExpressionString());
        assertNotNull(post.getFilterExpression());
        assertEquals("somePostFilterExpression", post.getFilterExpression().getExpressionString());
    }

    @Test
    public void interfaceAttributesAreIncluded() {
        List<ConfigAttribute> attrs = mds.getAttributes(notherListImpl1);

        assertEquals(1, attrs.size());
        assertTrue(attrs.get(0) instanceof PreInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute)attrs.get(0);
        assertNotNull(pre.getFilterExpression());
        assertNotNull(pre.getAuthorizeExpression());
        assertEquals("interfaceMethodAuthzExpression", pre.getAuthorizeExpression().getExpressionString());
        assertEquals("interfacePreFilterExpression", pre.getFilterExpression().getExpressionString());
    }

    @Test
    public void classAttributesTakesPrecedeceOverInterfaceAttributes() {
        List<ConfigAttribute> attrs = mds.getAttributes(notherListImpl2);

        assertEquals(1, attrs.size());
        assertTrue(attrs.get(0) instanceof PreInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute)attrs.get(0);
        assertNotNull(pre.getFilterExpression());
        assertNotNull(pre.getAuthorizeExpression());
        assertEquals("interfaceMethodAuthzExpression", pre.getAuthorizeExpression().getExpressionString());
        assertEquals("classMethodPreFilterExpression", pre.getFilterExpression().getExpressionString());
    }

    //~ Inner Classes ==================================================================================================

    public static interface ReturnVoid {
        public void doSomething(List param);
    }

    public static interface ReturnAList {
        public List doSomething(List param);
    }

    @PreAuthorize("interfaceAuthzExpression")
    public static interface ReturnAnotherList {
        @PreAuthorize("interfaceMethodAuthzExpression")
        @PreFilter(filterTarget="param", value="interfacePreFilterExpression")
        public List doSomething(List param);
    }


    @PreAuthorize("someExpression")
    public static class ReturnVoidImpl1 implements ReturnVoid {
        public void doSomething(List param) {}
    }

    @PreAuthorize("someExpression")
    public static class ReturnVoidImpl2 implements ReturnVoid {
        @PreFilter(filterTarget="param", value="somePreFilterExpression")
        public void doSomething(List param) {}
    }

    public static class ReturnVoidImpl3 implements ReturnVoid {
        @PreFilter(filterTarget="param", value="somePreFilterExpression")
        public void doSomething(List param) {}
    }

    public static class ReturnAListImpl1 implements ReturnAList {
        @PostFilter("somePostFilterExpression")
        public List doSomething(List param) {return param;}
    }

    public static class ReturnAListImpl2 implements ReturnAList {
        @PreAuthorize("someExpression")
        @PreFilter(filterTarget="param", value="somePreFilterExpression")
        @PostFilter("somePostFilterExpression")
        @PostAuthorize("somePostAuthorizeExpression")
        public List doSomething(List param) {return param;}
    }

    public static class ReturnAnotherListImpl1 implements ReturnAnotherList {
        public List doSomething(List param) {return param;}
    }

    public static class ReturnAnotherListImpl2 implements ReturnAnotherList {
        @PreFilter(filterTarget="param", value="classMethodPreFilterExpression")
        public List doSomething(List param) {return param;}
    }

}
