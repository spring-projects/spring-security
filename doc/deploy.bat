set MAVEN_OPTS=-Xmx1024m -XX:MaxPermSize=512m
call maven -Dmaven.jar.override=on -Dmaven.jar.clover-ant=1.3.3_01 clean
call maven -Dmaven.jar.override=on -Dmaven.jar.clover-ant=1.3.3_01 multiproject:clean
call maven -Dmaven.jar.override=on -Dmaven.jar.clover-ant=1.3.3_01 multiproject:artifact
call maven -X -Dmaven.jar.override=on -Dmaven.jar.clover-ant=1.3.3_01 multiproject:site > log.txt
