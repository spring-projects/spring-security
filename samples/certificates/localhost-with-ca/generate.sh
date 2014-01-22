openssl genrsa -des3 -passout pass:changeit -out ca.key 1024
openssl req -new -passin pass:changeit -key ca.key -out ca.csr
cp ca.key ca.key.org
openssl rsa -in ca.key.org -passin pass:changeit -out ca.key
openssl x509 -req -days 36500 -passin pass:changeit -in ca.csr -signkey ca.key -out ca.crt

keytool -genkey -storepass changeit -alias tomcat -keyalg RSA
keytool -storepass changeit -alias tomcat -certreq -file tomcat.csr
echo 02 > serial.txt
openssl x509 -CA ca.crt -passin pass:changeit -CAkey ca.key -CAserial serial.txt -req -in tomcat.csr -out tomcat.cer -days 36500
rm serial.txt
keytool -storepass changeit -import -alias ca -file ca.crt
keytool -storepass changeit -import -alias tomcat -file tomcat.cer
