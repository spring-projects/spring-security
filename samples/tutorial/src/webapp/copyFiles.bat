set spring=C:\dev\spring-framework-2.0-m4
set acegi=C:\dev\eclipse\workspaces\acegi\acegisecurity\samples\tutorial\target\acegi-security-sample-tutorial
mkdir %spring%\samples\petclinic\war\WEB-INF\lib
copy %acegi%\acegilogin.jsp %spring%\samples\petclinic\war
copy %acegi%\accessDenied.jsp %spring%\samples\petclinic\war
copy %acegi%\WEB-INF\users.properties %spring%\samples\petclinic\war\WEB-INF
copy %acegi%\WEB-INF\applicationContext-acegi-security.xml %spring%\samples\petclinic\war\WEB-INF
copy %acegi%\WEB-INF\lib\acegi-security-1.0.0.jar %spring%\samples\petclinic\war\WEB-INF\lib
copy %acegi%\WEB-INF\lib\oro-2.0.8.jar %spring%\samples\petclinic\war\WEB-INF\lib
copy %acegi%\WEB-INF\lib\commons-codec-1.3.jar %spring%\samples\petclinic\war\WEB-INF\lib

