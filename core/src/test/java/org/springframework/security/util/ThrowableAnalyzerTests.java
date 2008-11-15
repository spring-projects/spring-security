package org.springframework.security.util;

import java.lang.reflect.InvocationTargetException;

import junit.framework.TestCase;

/**
 * Test cases for {@link ThrowableAnalyzer}.
 *
 * @author Andreas Senft
 */
@SuppressWarnings("unchecked")
public class ThrowableAnalyzerTests extends TestCase {

    /**
     * Exception for testing purposes. The cause is not retrievable by {@link #getCause()}.
     */
    public static final class NonStandardException extends Exception {

        private Throwable cause;

        public NonStandardException(String message, Throwable cause) {
            super(message);
            this.cause = cause;
        }

        public Throwable resolveCause() {
            return this.cause;
        }
    }

    /**
     * <code>ThrowableCauseExtractor</code> for handling <code>NonStandardException</code> instances.
     */
    public static final class NonStandardExceptionCauseExtractor implements ThrowableCauseExtractor {

        public Throwable extractCause(Throwable throwable) {
            ThrowableAnalyzer.verifyThrowableHierarchy(throwable, NonStandardException.class);
            return ((NonStandardException) throwable).resolveCause();
        }

    }


    /**
     * An array of nested throwables for testing.
     * The cause of element 0 is element 1, the cause of element 1 is element 2 and so on.
     */
    private Throwable[] testTrace;

    /**
     * Plain <code>ThrowableAnalyzer</code>.
     */
    private ThrowableAnalyzer standardAnalyzer;

    /**
     * Enhanced <code>ThrowableAnalyzer</code> capable to process
     * <code>NonStandardException</code>s.
     */
    private ThrowableAnalyzer nonstandardAnalyzer;

    /**
     * @see junit.framework.TestCase#setUp()
     */
    @Override
    protected void setUp() throws Exception {
        super.setUp();

       // Set up test trace
       this.testTrace = new Throwable[7];
       this.testTrace[6] = new IllegalArgumentException("Test_6");
       this.testTrace[5] = new Throwable("Test_5",this.testTrace[6]);
       this.testTrace[4] = new InvocationTargetException(this.testTrace[5], "Test_4");
       this.testTrace[3] = new Exception("Test_3", this.testTrace[4]);
       this.testTrace[2] = new NonStandardException("Test_2", this.testTrace[3]);
       this.testTrace[1] = new RuntimeException("Test_1", this.testTrace[2]);
       this.testTrace[0] = new Exception("Test_0", this.testTrace[1]);

       // Set up standard analyzer
       this.standardAnalyzer = new ThrowableAnalyzer();

       // Set up nonstandard analyzer
       this.nonstandardAnalyzer = new ThrowableAnalyzer() {
           /**
            * @see org.springframework.security.util.ThrowableAnalyzer#initExtractorMap()
            */
           @Override
           protected void initExtractorMap() {
               super.initExtractorMap();
               // register extractor for NonStandardException
               registerExtractor(NonStandardException.class, new NonStandardExceptionCauseExtractor());
           }
       };
    }


    /**
     * @see junit.framework.TestCase#tearDown()
     */
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
    }

    public void testRegisterExtractorWithInvalidExtractor() {
        try {
            new ThrowableAnalyzer() {

                /**
                 * @see org.springframework.security.util.ThrowableAnalyzer#initExtractorMap()
                 */
                @Override
                protected void initExtractorMap() {
                    // null is no valid extractor
                    super.registerExtractor(Exception.class, null);
                }
            };

            fail("IllegalArgumentExpected");
        } catch (IllegalArgumentException e) {
            // ok
        }
    }

    public void testGetRegisteredTypes() {

        Class[] registeredTypes = this.nonstandardAnalyzer.getRegisteredTypes();

        for (int i = 0; i < registeredTypes.length; ++i) {
            Class clazz = registeredTypes[i];

            // The most specific types have to occur first.
            for (int j = 0; j < i; ++j) {
                Class prevClazz = registeredTypes[j];

                assertFalse("Unexpected order of registered classes: "
                        + prevClazz + " is assignable from " + clazz, prevClazz.isAssignableFrom(clazz));
            }
        }
    }

    public void testDetermineCauseChainWithNoExtractors() {
        ThrowableAnalyzer analyzer = new ThrowableAnalyzer() {

            /**
             * @see org.springframework.security.util.ThrowableAnalyzer#initExtractorMap()
             */
            @Override
            protected void initExtractorMap() {
                // skip default initialization
            }
        };

        assertEquals("Unexpected number of registered types", 0, analyzer.getRegisteredTypes().length);

        Throwable t = this.testTrace[0];
        Throwable[] chain = analyzer.determineCauseChain(t);
        // Without extractors only the root throwable is available
        assertEquals("Unexpected chain size", 1, chain.length);
        assertEquals("Unexpected chain entry", t, chain[0]);
    }

    public void testDetermineCauseChainWithDefaultExtractors() {
        ThrowableAnalyzer analyzer = this.standardAnalyzer;

        assertEquals("Unexpected number of registered types", 2, analyzer.getRegisteredTypes().length);

        Throwable[] chain = analyzer.determineCauseChain(this.testTrace[0]);

        // Element at index 2 is a NonStandardException which cannot be analyzed further by default
        assertEquals("Unexpected chain size", 3, chain.length);
        for (int i = 0; i < 3; ++i) {
            assertEquals("Unexpected chain entry: " + i, this.testTrace[i], chain[i]);
        }
    }

    public void testDetermineCauseChainWithCustomExtractors() {
        ThrowableAnalyzer analyzer = this.nonstandardAnalyzer;

        Throwable[] chain = analyzer.determineCauseChain(this.testTrace[0]);

        assertEquals("Unexpected chain size", this.testTrace.length, chain.length);
        for (int i = 0; i < chain.length; ++i) {
            assertEquals("Unexpected chain entry: " + i, this.testTrace[i], chain[i]);
        }
    }

    public void testGetFirstThrowableOfTypeWithSuccess1() {
        ThrowableAnalyzer analyzer = this.nonstandardAnalyzer;

        Throwable[] chain = analyzer.determineCauseChain(this.testTrace[0]);

        Throwable result = analyzer.getFirstThrowableOfType(Exception.class, chain);

        assertNotNull("null not expected", result);
        assertEquals("Unexpected throwable found", this.testTrace[0], result);
    }

    public void testGetFirstThrowableOfTypeWithSuccess2() {
        ThrowableAnalyzer analyzer = this.nonstandardAnalyzer;

        Throwable[] chain = analyzer.determineCauseChain(this.testTrace[0]);

        Throwable result = analyzer.getFirstThrowableOfType(NonStandardException.class, chain);

        assertNotNull("null not expected", result);
        assertEquals("Unexpected throwable found", this.testTrace[2], result);
    }

    public void testGetFirstThrowableOfTypeWithFailure() {
        ThrowableAnalyzer analyzer = this.nonstandardAnalyzer;

        Throwable[] chain = analyzer.determineCauseChain(this.testTrace[0]);

        // IllegalStateException not in trace
        Throwable result = analyzer.getFirstThrowableOfType(IllegalStateException.class, chain);

        assertNull("null expected", result);
    }

    public void testVerifyThrowableHierarchyWithExactType() {

        Throwable throwable = new IllegalStateException("Test");
        ThrowableAnalyzer.verifyThrowableHierarchy(throwable, IllegalStateException.class);
        // No exception expected
    }

    public void testVerifyThrowableHierarchyWithCompatibleType() {

        Throwable throwable = new IllegalStateException("Test");
        ThrowableAnalyzer.verifyThrowableHierarchy(throwable, Exception.class);
        // No exception expected
    }

    public void testVerifyThrowableHierarchyWithNull() {
        try {
            ThrowableAnalyzer.verifyThrowableHierarchy(null, Throwable.class);
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            // ok
        }
    }

    public void testVerifyThrowableHierarchyWithNonmatchingType() {

        Throwable throwable = new IllegalStateException("Test");
        try {
            ThrowableAnalyzer.verifyThrowableHierarchy(throwable, InvocationTargetException.class);
            fail("IllegalArgumentException expected");
        } catch (IllegalArgumentException e) {
            // ok
        }
    }
}
