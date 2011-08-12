package org.springframework.security.access.expression.method;

import static org.junit.Assert.*;

import java.lang.annotation.ElementType;
import java.lang.annotation.Inherited;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.intercept.method.MockMethodInvocation;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PostFilter;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.access.prepost.PreFilter;
import org.springframework.security.access.prepost.PrePostAnnotationSecurityMetadataSource;

/**
 *
 * @author Luke Taylor
 * @since 3.0
 */
public class PrePostAnnotationSecurityMetadataSourceTests {
    private PrePostAnnotationSecurityMetadataSource mds =
        new PrePostAnnotationSecurityMetadataSource(new ExpressionBasedAnnotationAttributeFactory(new DefaultMethodSecurityExpressionHandler()));

    private MockMethodInvocation voidImpl1;
    private MockMethodInvocation voidImpl2;
    private MockMethodInvocation voidImpl3;
    private MockMethodInvocation listImpl1;
    private MockMethodInvocation notherListImpl1;
    private MockMethodInvocation notherListImpl2;
    private MockMethodInvocation annotatedAtClassLevel;
    private MockMethodInvocation annotatedAtInterfaceLevel;
    private MockMethodInvocation annotatedAtMethodLevel;

    @Before
    public void setUpData() throws Exception {
        voidImpl1 = new MockMethodInvocation(new ReturnVoidImpl1(), ReturnVoid.class, "doSomething", List.class);
        voidImpl2 = new MockMethodInvocation(new ReturnVoidImpl2(), ReturnVoid.class, "doSomething", List.class);
        voidImpl3 = new MockMethodInvocation(new ReturnVoidImpl3(), ReturnVoid.class, "doSomething", List.class);
        listImpl1 = new MockMethodInvocation(new ReturnAListImpl1(), ReturnAList.class, "doSomething", List.class);
        notherListImpl1 = new MockMethodInvocation(new ReturnAnotherListImpl1(), ReturnAnotherList.class, "doSomething", List.class);
        notherListImpl2 = new MockMethodInvocation(new ReturnAnotherListImpl2(), ReturnAnotherList.class, "doSomething", List.class);
        annotatedAtClassLevel = new MockMethodInvocation(new CustomAnnotationAtClassLevel(), ReturnVoid.class, "doSomething", List.class);
        annotatedAtInterfaceLevel = new MockMethodInvocation(new CustomAnnotationAtInterfaceLevel(), ReturnVoid2.class, "doSomething", List.class);
        annotatedAtMethodLevel = new MockMethodInvocation(new CustomAnnotationAtMethodLevel(), ReturnVoid.class, "doSomething", List.class);
    }

    @Test
    public void classLevelPreAnnotationIsPickedUpWhenNoMethodLevelExists() throws Exception {
        ConfigAttribute[] attrs = mds.getAttributes(voidImpl1).toArray(new ConfigAttribute[0]);

        assertEquals(1, attrs.length);
        assertTrue(attrs[0] instanceof PreInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs[0];
        assertNotNull(pre.getAuthorizeExpression());
        assertEquals("someExpression", pre.getAuthorizeExpression().getExpressionString());
        assertNull(pre.getFilterExpression());
    }

    @Test
    public void mixedClassAndMethodPreAnnotationsAreBothIncluded() {
        ConfigAttribute[] attrs = mds.getAttributes(voidImpl2).toArray(new ConfigAttribute[0]);

        assertEquals(1, attrs.length);
        assertTrue(attrs[0] instanceof PreInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs[0];
        assertEquals("someExpression", pre.getAuthorizeExpression().getExpressionString());
        assertNotNull(pre.getFilterExpression());
        assertEquals("somePreFilterExpression", pre.getFilterExpression().getExpressionString());
    }

    @Test
    public void methodWithPreFilterOnlyIsAllowed() {
        ConfigAttribute[] attrs = mds.getAttributes(voidImpl3).toArray(new ConfigAttribute[0]);

        assertEquals(1, attrs.length);
        assertTrue(attrs[0] instanceof PreInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs[0];
        assertEquals("permitAll", pre.getAuthorizeExpression().getExpressionString());
        assertNotNull(pre.getFilterExpression());
        assertEquals("somePreFilterExpression", pre.getFilterExpression().getExpressionString());
    }

    @Test
    public void methodWithPostFilterOnlyIsAllowed() {
        ConfigAttribute[] attrs = mds.getAttributes(listImpl1).toArray(new ConfigAttribute[0]);

        assertEquals(2, attrs.length);
        assertTrue(attrs[0] instanceof PreInvocationExpressionAttribute);
        assertTrue(attrs[1] instanceof PostInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute) attrs[0];
        PostInvocationExpressionAttribute post = (PostInvocationExpressionAttribute) attrs[1];
        assertEquals("permitAll", pre.getAuthorizeExpression().getExpressionString());
        assertNotNull(post.getFilterExpression());
        assertEquals("somePostFilterExpression", post.getFilterExpression().getExpressionString());
    }

    @Test
    public void interfaceAttributesAreIncluded() {
        ConfigAttribute[] attrs = mds.getAttributes(notherListImpl1).toArray(new ConfigAttribute[0]);

        assertEquals(1, attrs.length);
        assertTrue(attrs[0] instanceof PreInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute)attrs[0];
        assertNotNull(pre.getFilterExpression());
        assertNotNull(pre.getAuthorizeExpression());
        assertEquals("interfaceMethodAuthzExpression", pre.getAuthorizeExpression().getExpressionString());
        assertEquals("interfacePreFilterExpression", pre.getFilterExpression().getExpressionString());
    }

    @Test
    public void classAttributesTakesPrecedeceOverInterfaceAttributes() {
        ConfigAttribute[] attrs = mds.getAttributes(notherListImpl2).toArray(new ConfigAttribute[0]);

        assertEquals(1, attrs.length);
        assertTrue(attrs[0] instanceof PreInvocationExpressionAttribute);
        PreInvocationExpressionAttribute pre = (PreInvocationExpressionAttribute)attrs[0];
        assertNotNull(pre.getFilterExpression());
        assertNotNull(pre.getAuthorizeExpression());
        assertEquals("interfaceMethodAuthzExpression", pre.getAuthorizeExpression().getExpressionString());
        assertEquals("classMethodPreFilterExpression", pre.getFilterExpression().getExpressionString());
    }

    @Test
    public void customAnnotationAtClassLevelIsDetected() throws Exception {
        ConfigAttribute[] attrs = mds.getAttributes(annotatedAtClassLevel).toArray(new ConfigAttribute[0]);

        assertEquals(1, attrs.length);
    }

    @Test
    public void customAnnotationAtInterfaceLevelIsDetected() throws Exception {
        ConfigAttribute[] attrs = mds.getAttributes(annotatedAtInterfaceLevel).toArray(new ConfigAttribute[0]);

        assertEquals(1, attrs.length);
    }

    @Test
    public void customAnnotationAtMethodLevelIsDetected() throws Exception {
        ConfigAttribute[] attrs = mds.getAttributes(annotatedAtMethodLevel).toArray(new ConfigAttribute[0]);

        assertEquals(1, attrs.length);
    }

    //~ Inner Classes ==================================================================================================

    public static interface ReturnVoid {
        public void doSomething(List<?> param);
    }

    public static interface ReturnAList {
        public List<?> doSomething(List<?> param);
    }

    @PreAuthorize("interfaceAuthzExpression")
    public static interface ReturnAnotherList {
        @PreAuthorize("interfaceMethodAuthzExpression")
        @PreFilter(filterTarget="param", value="interfacePreFilterExpression")
        public List<?> doSomething(List<?> param);
    }


    @PreAuthorize("someExpression")
    public static class ReturnVoidImpl1 implements ReturnVoid {
        public void doSomething(List<?> param) {}
    }

    @PreAuthorize("someExpression")
    public static class ReturnVoidImpl2 implements ReturnVoid {
        @PreFilter(filterTarget="param", value="somePreFilterExpression")
        public void doSomething(List<?> param) {}
    }

    public static class ReturnVoidImpl3 implements ReturnVoid {
        @PreFilter(filterTarget="param", value="somePreFilterExpression")
        public void doSomething(List<?> param) {}
    }

    public static class ReturnAListImpl1 implements ReturnAList {
        @PostFilter("somePostFilterExpression")
        public List<?> doSomething(List<?> param) {return param;}
    }

    public static class ReturnAListImpl2 implements ReturnAList {
        @PreAuthorize("someExpression")
        @PreFilter(filterTarget="param", value="somePreFilterExpression")
        @PostFilter("somePostFilterExpression")
        @PostAuthorize("somePostAuthorizeExpression")
        public List<?> doSomething(List<?> param) {return param;}
    }

    public static class ReturnAnotherListImpl1 implements ReturnAnotherList {
        public List<?> doSomething(List<?> param) {return param;}
    }

    public static class ReturnAnotherListImpl2 implements ReturnAnotherList {
        @PreFilter(filterTarget="param", value="classMethodPreFilterExpression")
        public List<?> doSomething(List<?> param) {return param;}
    }

    @Target({ ElementType.METHOD, ElementType.TYPE })
    @Retention(RetentionPolicy.RUNTIME)
    @Inherited
    @PreAuthorize("customAnnotationExpression")
    public @interface CustomAnnotation {}

    @CustomAnnotation
    public static interface ReturnVoid2 {
        public void doSomething(List<?> param);
    }

    @CustomAnnotation
    public static class CustomAnnotationAtClassLevel implements ReturnVoid {
        public void doSomething(List<?> param) {}
    }

    public static class CustomAnnotationAtInterfaceLevel implements ReturnVoid2 {
        public void doSomething(List<?> param) {}
    }

    public static class CustomAnnotationAtMethodLevel implements ReturnVoid {
        @CustomAnnotation
        public void doSomething(List<?> param) {}
    }
}
