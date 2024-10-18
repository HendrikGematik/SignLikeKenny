javac -cp .:lib/*:src -d out src/SignLikeKenny.java
java -cp .:lib/*:out SignLikeKenny
openssl cms -sign -cades -in single_byte.bin -signer ~/DespicableMe/Gru.pem -inkey ~/DespicableMe/Gru.prv.pem -outform DER -binary -nodetach -out signature.der
ls -l signed_data.asn1 | awk '{print $5}'
ls -l signature.der | awk '{print $5}'