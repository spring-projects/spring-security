package egovframework.com.security.securityPass;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.lang.annotation.Annotation;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * fileName       : SecurityUtils
 * author         : crlee
 * date           : 2023/06/21
 * description    : A feature that returns the values of
 *                  @GetMapping,
 *                  @PostMapping,
 *                  @PutMapping,
 *                  @DeleteMapping,
 *                  @PatchMapping annotations
 *                  for methods with the '@SecurityPass' annotation attached
 * ===========================================================
 * DATE              AUTHOR             NOTE
 * -----------------------------------------------------------
 * 2023/06/21        crlee       최초 생성
 */
@Configuration
public class SecurityUtils {

    /*
    * GetMapping,PostMapping,PutMapping,PatchMapping의 value return
    * */
    public String[] getSecurityPassUrls(){

        List<String> auth_whitelists = new ArrayList<>();
        try{
            auth_whitelists = searchMappingUrls();
        }catch (Exception e){
            e.printStackTrace();
        }

        return auth_whitelists.toArray(new String[0]);
    }
    private List<String> searchMappingUrls() throws ClassNotFoundException,
            NoSuchMethodException, SecurityException, InvocationTargetException, IllegalAccessException, MalformedURLException {
            List<Class<? extends Annotation>> mappingAnnotations = Arrays.asList(
                    GetMapping.class,
                    PostMapping.class,
                    PutMapping.class,
                    DeleteMapping.class,
                    PatchMapping.class
            );

            List<Class> classes = findClasses(getTopPackage());
            List<String> auth_whitelists = new ArrayList<>();
            for (Class clazz : classes) {
                for(Method method : clazz.getMethods()){
                    if (method.isAnnotationPresent(SecurityPass.class)) {
                        for (Class<? extends Annotation> annotationClass : mappingAnnotations) {
                            if( method.isAnnotationPresent(annotationClass) ){
                                String[] values = (String[]) method.getAnnotation(annotationClass).getClass().getMethod("value").invoke(method.getAnnotation(annotationClass));
                                auth_whitelists.addAll(Arrays.asList(values));
                            };
                        }
                    }
                }
            }
        return auth_whitelists;
    }
    private String getTopPackage(){
        Package basePackage = SecurityUtils.class.getPackage();
        String packageName = basePackage.getName();
        String[] packageLevels = packageName.split("\\.");
        return packageLevels[0];
    }
    private List<Class> findClasses(String topPackage) throws ClassNotFoundException, MalformedURLException {
        List<Class> classes = new ArrayList<>();

        URL resourceUrl = new URL( getClass().getProtectionDomain().getCodeSource().getLocation() , topPackage );
        if (resourceUrl == null) {
            throw new ClassNotFoundException("No resource found for : " + topPackage);
        }

        File directory = new File(resourceUrl.getFile());
        if (!directory.exists()) {
            throw new ClassNotFoundException(topPackage + " not found.");
        }

        findClassesRecursive(topPackage, directory, classes);
        return classes;
    }

    private void findClassesRecursive(String packageName, File directory, List<Class> classes) throws ClassNotFoundException {
        File[] files = directory.listFiles();
        if (files != null) {
            for (File file : files) {
                String fileName = file.getName();
                if (file.isDirectory()) {
                    String subPackageName = packageName + "." + fileName;
                    findClassesRecursive(subPackageName, file, classes);
                } else if (file.isFile() && fileName.endsWith(".class")) {
                    String className = packageName + '.' + fileName.substring(0, fileName.length() - 6);
                    Class clazz = Class.forName(className);
                    classes.add(clazz);
                }
            }
        }
    }

}
