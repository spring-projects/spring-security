package org.springframework.security.util;

import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

/**
 * Handler for analyzing {@link Throwable} instances.
 *
 * Can be subclassed to customize its behavior.
 * 
 * @author Andreas Senft
 * @since 2.0
 * @version $Id$
 */
public class ThrowableAnalyzer {

    /**
     * Default extractor for {@link Throwable} instances.
     * 
     * @see Throwable#getCause()
     */
    public static final ThrowableCauseExtractor DEFAULT_EXTRACTOR
        = new ThrowableCauseExtractor() {
            public Throwable extractCause(Throwable throwable) {
                return throwable.getCause();
            }
        };
    
    /**
     * Default extractor for {@link InvocationTargetException} instances.
     * 
     * @see InvocationTargetException#getTargetException()
     */
    public static final ThrowableCauseExtractor INVOCATIONTARGET_EXTRACTOR 
        = new ThrowableCauseExtractor() {
            public Throwable extractCause(Throwable throwable) {
                verifyThrowableHierarchy(throwable, InvocationTargetException.class);
                return ((InvocationTargetException) throwable).getTargetException();
            }
        };

    /**
     * Comparator to order classes ascending according to their hierarchy relation.
     * If two classes have a hierarchical relation, the "higher" class is considered 
     * to be greater by this comparator.<br>
     * For hierarchically unrelated classes their fully qualified name will be compared. 
     */
    private static final Comparator CLASS_HIERARCHY_COMPARATOR = new Comparator() {

        public int compare(Object o1, Object o2) {
            Class class1 = (Class) o1;
            Class class2 = (Class) o2;
            
            if (class1.isAssignableFrom(class2)) {
                return 1;
            } else if (class2.isAssignableFrom(class1)) {
                return -1;
            } else {
                return class1.getName().compareTo(class2.getName());
            }
        }
        
    };
        

    /**
     * Map of registered cause extractors.
     * key: Class<Throwable>; value: ThrowableCauseExctractor
     */
    private final Map extractorMap;
    
    
    /**
     * Creates a new <code>ThrowableAnalyzer</code> instance.
     */
    public ThrowableAnalyzer() {
        this.extractorMap = new TreeMap(CLASS_HIERARCHY_COMPARATOR);
        
        initExtractorMap();
    }
    
    /**
     * Registers a <code>ThrowableCauseExtractor</code> for the specified type.
     * <i>Can be used in subclasses overriding {@link #initExtractorMap()}.</i>
     * 
     * @param throwableType the type (has to be a subclass of <code>Throwable</code>)
     * @param extractor the associated <code>ThrowableCauseExtractor</code> (not <code>null</code>)
     * 
     * @throws IllegalArgumentException if one of the arguments is invalid
     */
    protected final void registerExtractor(Class throwableType, ThrowableCauseExtractor extractor) {
        verifyThrowableType(throwableType);

        if (extractor == null) {
            throw new IllegalArgumentException("Invalid extractor: null");
        }

        this.extractorMap.put(throwableType, extractor);
    }

    /**
     * Initializes associations between <code>Throwable</code>s and <code>ThrowableCauseExtractor</code>s.
     * The default implementation performs the following registrations:
     * <li>{@link #DEFAULT_EXTRACTOR} for {@link Throwable}</li>
     * <li>{@link #INVOCATIONTARGET_EXTRACTOR} for {@link InvocationTargetException}</li>
     * <br>
     * Subclasses overriding this method are encouraged to invoke the super method to perform the
     * default registrations. They can register additional extractors as required.
     * <p>
     * Note: An extractor registered for a specific type is applicable for that type <i>and all subtypes thereof</i>.
     * However, extractors registered to more specific types are guaranteed to be resolved first.
     * So in the default case InvocationTargetExceptions will be handled by {@link #INVOCATIONTARGET_EXTRACTOR}
     * while all other throwables are handled by {@link #DEFAULT_EXTRACTOR}.
     * 
     * @see #registerExtractor(Class, ThrowableCauseExtractor)
     */
    protected void initExtractorMap() {
        registerExtractor(InvocationTargetException.class, INVOCATIONTARGET_EXTRACTOR);
        registerExtractor(Throwable.class, DEFAULT_EXTRACTOR);
    }
    
    /**
     * Returns an array containing the classes for which extractors are registered.
     * The order of the classes is the order in which comparisons will occur for
     * resolving a matching extractor.
     * 
     * @return the types for which extractors are registered
     */
    final Class[] getRegisteredTypes() {
        List typeList = new ArrayList(this.extractorMap.keySet());
        return (Class[]) typeList.toArray(new Class[typeList.size()]);
    }
    
    /**
     * Determines the cause chain of the provided <code>Throwable</code>.
     * The returned array contains all throwables extracted from the stacktrace, using the registered
     * {@link ThrowableCauseExtractor extractors}. The elements of the array are ordered:
     * The first element is the passed in throwable itself. The following elements
     * appear in their order downward the stacktrace.
     * <p>
     * Note: If no {@link ThrowableCauseExtractor} is registered for this instance 
     * then the returned array will always only contain the passed in throwable.
     * 
     * @param throwable the <code>Throwable</code> to analyze
     * @return an array of all determined throwables from the stacktrace
     * 
     * @throws IllegalArgumentException if the throwable is <code>null</code>
     * 
     * @see #initExtractorMap()
     */
    public final Throwable[] determineCauseChain(Throwable throwable) {
        if (throwable == null) {
            throw new IllegalArgumentException("Invalid throwable: null");
        }
        
        List chain = new ArrayList();
        Throwable currentThrowable = throwable;
        
        while (currentThrowable != null) {
            chain.add(currentThrowable);
            currentThrowable = extractCause(currentThrowable);
        }
        
        return (Throwable[]) chain.toArray(new Throwable[chain.size()]);
    }
    
    /**
     * Extracts the cause of the given throwable using an appropriate extractor.
     * 
     * @param throwable the <code>Throwable</code> (not <code>null</code>
     * @return the cause, may be <code>null</code> if none could be resolved
     */
    private Throwable extractCause(Throwable throwable) {
        for (Iterator iter = this.extractorMap.entrySet().iterator(); iter.hasNext(); ) {
            Map.Entry entry = (Map.Entry) iter.next();
            
            Class throwableType = (Class) entry.getKey();
            if (throwableType.isInstance(throwable)) {
                ThrowableCauseExtractor extractor = (ThrowableCauseExtractor) entry.getValue();
                return extractor.extractCause(throwable);
            }
        }
        
        return null;
    }
    
    /**
     * Returns the first throwable from the passed in array that is assignable to the provided type.
     * A returned instance is safe to be cast to the specified type.
     * <p>
     * If the passed in array is null or empty this method returns <code>null</code>.
     * 
     * @param throwableType the type to look for
     * @param chain the array (will be processed in element order)
     * @return the found <code>Throwable</code>, <code>null</code> if not found
     * 
     * @throws IllegalArgumentException if the provided type is <code>null</code> 
     * or no subclass of <code>Throwable</code>
     */
    public final Throwable getFirstThrowableOfType(Class throwableType, Throwable[] chain) {
        verifyThrowableType(throwableType);
        
        if (chain != null) {
            for (int i = 0; i < chain.length; ++i) {
                Throwable t = chain[i];
                
                if ((t != null) && throwableType.isInstance(t)) {
                    return t;
                }
            }
        }
        
        return null;
    }
    
    /**
     * Convenience method for verifying that the passed in class refers to a valid 
     * subclass of <code>Throwable</code>.
     * 
     * @param throwableType the type to check
     * 
     * @throws IllegalArgumentException if <code>typeToCheck</code> is either <code>null</code>
     * or not assignable to <code>expectedBaseType</code>
     */
    private static void verifyThrowableType(Class throwableType) {
        if (throwableType == null) {
            throw new IllegalArgumentException("Invalid type: null");
        }
        if (!Throwable.class.isAssignableFrom(throwableType)) {
            throw new IllegalArgumentException("Invalid type: '" 
                    + throwableType.getName() 
                    + "'. Has to be a subclass of '" + Throwable.class.getName() + "'");
        }
    }
    
    /**
     * Verifies that the provided throwable is a valid subclass of the provided type (or of the type itself).
     * If <code>expectdBaseType</code> is <code>null</code>, no check will be performed.
     * <p>
     * Can be used for verification purposes in implementations 
     * of {@link ThrowableCauseExtractor extractors}.
     * 
     * @param throwable the <code>Throwable</code> to check
     * @param expectedBaseType the type to check against
     * 
     * @throws IllegalArgumentException if <code>throwable</code> is either <code>null</code>
     * or its type is not assignable to <code>expectedBaseType</code>
     */
    public static final void verifyThrowableHierarchy(Throwable throwable, Class expectedBaseType) {
        if (expectedBaseType == null) {
            return;
        }
        
        if (throwable == null) {
            throw new IllegalArgumentException("Invalid throwable: null");
        }
        Class throwableType = throwable.getClass();
        
        if (!expectedBaseType.isAssignableFrom(throwableType)) {
            throw new IllegalArgumentException("Invalid type: '" 
                    + throwableType.getName() 
                    + "'. Has to be a subclass of '" + expectedBaseType.getName() + "'");
        }
    }
}
