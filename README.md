# PKCS#11 for TLS client authentication example

This project is an example of using PKCS#11 for TLS client authentication,
without using a real smart card.

This project uses [SoftHSM v2](https://github.com/opendnssec/SoftHSMv2) to
create a virtual PKCS#11-enabled smart card, and `keytool` to interact with it -
i.e., to import private keys and certificates into it.

# Prerequisites

* Java 17+
* Maven 3+

These instructions have been tested on MacOS using an M1 Mac Air.

# Install SoftHSM

```bash
brew install softhsm
```

# Build

```bash
softhsm2-util --delete-token --token myToken ; \
  rm -f *.pem *.cer *.p12 && \
  mvn clean install
```

# Set up the PKCS#11 keystore

```bash
softhsm2-util --init-token --slot 0 --label "myToken" --pin 1234 --so-pin 5678
```

# Create the client keystore

Create a PEM key pair for TLS authentication and convert it into PKCS#12 format
to be used as the client keystore:

```bash
openssl genpkey -algorithm RSA -out client-key.pem \
  -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key client-key.pem -out client-cert.pem \
  -days 365 -subj "/CN=client"
openssl pkcs12 -export -in client-cert.pem -inkey client-key.pem \
  -out client-keystore.p12 -name client -password pass:changeit
```

Import the client keystore into SoftHSM:

```bash
keytool -importkeystore -srckeystore client-keystore.p12 -srcstoretype PKCS12 \
  -srcstorepass changeit -destkeystore NONE -deststoretype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 -providerArg pkcs11.cfg \
  -alias client -deststorepass 1234
```

# Create the server truststore

Let's create the server truststore by extracting the certificate from the
client keystore (in a production scenario, the private key must NOT be shared):

```bash
keytool -exportcert -keystore client-keystore.p12 -storetype PKCS12 \
  -alias client -file client-cert.cer -storepass changeit

keytool -importcert -file client-cert.cer \
  -keystore server-truststore.p12 \
  -storetype PKCS12 -alias client \
  -storepass changeit -noprompt
```

# Create the server keystore

```bash
openssl genpkey -algorithm RSA -out server-key.pem \
  -pkeyopt rsa_keygen_bits:2048
openssl req -new -x509 -key server-key.pem -out server-cert.pem \
  -days 365 -subj "/CN=localhost"
openssl pkcs12 -export -in server-cert.pem -inkey server-key.pem \
  -out server-keystore.p12 -name server -password pass:changeit
```

# Create the client truststore

Let's create the client truststore by extracting the certificate from the
server keystore (in a production scenario, the private key must NOT be shared):

```bash
keytool -exportcert -keystore server-keystore.p12 -storetype PKCS12 \
  -alias server -file server-cert.cer -storepass changeit

keytool -importcert -file server-cert.cer \
  -keystore client-truststore.p12 \
  -storetype PKCS12 -alias server \
  -storepass changeit -noprompt
```

# Listing the contents of the keystores and trust stores

The PCS#11-based client keystore must contain both a private key and a
certificate, because it's used to perform TLS authentication:

```bash
keytool -list -keystore NONE \
  -storepass 1234 \
  -storetype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 -providerArg pkcs11.cfg
  
Your keystore contains 1 entry

client, PrivateKeyEntry,
Certificate fingerprint (SHA-256): ...
```

The PKCS#12 client trust store must contain only a certificate (the server's),
without a private key:

```bash
keytool -list -keystore client-truststore.p12 \
  -storepass changeit \
  -storetype PKCS12

Your keystore contains 1 entry

server, 14 Jul 2024, trustedCertEntry,
Certificate fingerprint (SHA-256): ...
```

The PKCS#12 server keystore must contain both a private key and a certificate,
because it's used to perform the TLS handshake:

```bash
keytool -list -keystore server-keystore.p12 \
  -storepass changeit \
  -storetype PKCS12

Your keystore contains 1 entry

server, 14 Jul 2024, PrivateKeyEntry,
Certificate fingerprint (SHA-256): ...
```

The PKCS#12 server truststore must only contain a certificate, without a private key,
because it's used to verify the identity of the client with TLS authentication:

```bash
keytool -list -keystore server-truststore.p12 \
  -storepass changeit \
  -storetype PKCS12

Your keystore contains 1 entry

client, 14 Jul 2024, trustedCertEntry,
Certificate fingerprint (SHA-256): ...
```

# Starting the server

```bash
mvn jetty:run -f jetty-tls-server
```

# Running the client with system properties

The simplest approach is to pass the security information via system properties,
because it requires less code and it's easier to configure the client without
touching the code. However, all TLS clients within the JVM will use these
properties.

To run the client, issue this command in another tab:

```bash
java -cp pkcs11-tls-client/target/pkcs11-tls-client-1.0-SNAPSHOT.jar \
  -Djavax.net.ssl.keyStoreType=PKCS11 \
  -Djavax.net.ssl.keyStore=NONE \
  -Djavax.net.ssl.keyStorePassword=1234 \
  -Djavax.net.ssl.trustStoreType=PKCS12 \
  -Djavax.net.ssl.trustStore=client-truststore.p12 \
  -Djavax.net.ssl.trustStorePassword=changeit \
  org.example.SysPropsPKCS11HttpsClient \
  pkcs11.cfg https://localhost:8443/hello 

Response Code: 200
Response Content: <h1>Hello Servlet</h1>session=node0irhb3hsmmpdo1rxdo8niyf9w90
```

Providing the wrong truststore (e.g. `client-keystore.p12` instead of
`client-truststore.p12`) yields the following error:

```bash
java -cp pkcs11-tls-client/target/pkcs11-tls-client-1.0-SNAPSHOT.jar \
  -Djavax.net.ssl.keyStoreType=PKCS11 \
  -Djavax.net.ssl.keyStore=NONE \
  -Djavax.net.ssl.keyStorePassword=1234 \
  -Djavax.net.ssl.trustStoreType=PKCS12 \
  -Djavax.net.ssl.trustStore=client-keystore.p12 \
  -Djavax.net.ssl.trustStorePassword=changeit \
  org.example.SysPropsPKCS11HttpsClient \
  pkcs11.cfg https://localhost:8443/hello 

Caused by: sun.security.validator.ValidatorException: PKIX path building failed:
sun.security.provider.certpath.SunCertPathBuilderException:
unable to find valid certification path to requested target
```

Deleting the 'client' alias, the connection fails:

```bash
keytool -delete -alias client -keystore NONE -storetype PKCS11 \
  -providerClass sun.security.pkcs11.SunPKCS11 \
  -providerArg pkcs11.cfg -storepass 1234
```

```bash
java -cp pkcs11-tls-client/target/pkcs11-tls-client-1.0-SNAPSHOT.jar \
  -Djavax.net.ssl.keyStoreType=PKCS11 \
  -Djavax.net.ssl.keyStore=NONE \
  -Djavax.net.ssl.keyStorePassword=1234 \
  -Djavax.net.ssl.trustStoreType=PKCS12 \
  -Djavax.net.ssl.trustStore=client-truststore.p12 \
  -Djavax.net.ssl.trustStorePassword=changeit \
  org.example.SysPropsPKCS11HttpsClient \
  pkcs11.cfg https://localhost:8443/hello 

Exception in thread "main" java.io.IOException: Error writing to server
...
```

More details can be obtained by debugging the SSL layer:

```bash
java -Djavax.net.debug=ssl:handshake \
  -cp pkcs11-tls-client/target/pkcs11-tls-client-1.0-SNAPSHOT.jar \
  -Djavax.net.ssl.keyStoreType=PKCS11 \
  -Djavax.net.ssl.keyStore=NONE \
  -Djavax.net.ssl.keyStorePassword=1234 \
  -Djavax.net.ssl.trustStoreType=PKCS12 \
  -Djavax.net.ssl.trustStore=client-truststore.p12 \
  -Djavax.net.ssl.trustStorePassword=changeit \
  org.example.SysPropsPKCS11HttpsClient \
  pkcs11.cfg https://localhost:8443/hello 
```

The same can be done with cURL:

```bash
curl -v https://localhost:8443/hello \
  --cacert server-cert.pem \
  --key client-key.pem \
  --cert client-cert.pem

* Host localhost:8443 was resolved.
* IPv6: ::1
* IPv4: 127.0.0.1
*   Trying [::1]:8443...
* Connected to localhost (::1) port 8443
* ALPN: curl offers h2,http/1.1
* (304) (OUT), TLS handshake, Client hello (1):
*  CAfile: server-cert.pem
*  CApath: none
* (304) (IN), TLS handshake, Server hello (2):
* (304) (IN), TLS handshake, Unknown (8):
* (304) (IN), TLS handshake, Request CERT (13):
* (304) (IN), TLS handshake, Certificate (11):
* (304) (IN), TLS handshake, CERT verify (15):
* (304) (IN), TLS handshake, Finished (20):
* (304) (OUT), TLS handshake, Certificate (11):
* (304) (OUT), TLS handshake, CERT verify (15):
* (304) (OUT), TLS handshake, Finished (20):
* SSL connection using TLSv1.3 / AEAD-AES256-GCM-SHA384 / [blank] / UNDEF
* ALPN: server did not agree on a protocol. Uses default.
* Server certificate:
*  subject: CN=localhost
*  start date: Jul 14 14:04:09 2024 GMT
*  expire date: Jul 14 14:04:09 2025 GMT
*  common name: localhost (matched)
*  issuer: CN=localhost
*  SSL certificate verify ok.
* using HTTP/1.x
> GET /hello HTTP/1.1
> Host: localhost:8443
> User-Agent: curl/8.6.0
> Accept: */*
>
< HTTP/1.1 200 OK
< Server: Jetty(12.0.10)
< Date: Sun, 14 Jul 2024 14:22:56 GMT
< Content-Type: text/html;charset=utf-8
< Set-Cookie: JSESSIONID=node01dbm04p04x3r0xjohs07k1d6610.node0; Path=/; Secure
< Expires: Thu, 01 Jan 1970 00:00:00 GMT
< Content-Length: 64
<
<h1>Hello Servlet</h1>
session=node01dbm04p04x3r0xjohs07k1d6610
* Connection #0 to host localhost left intact
```

# Running the programmatic client

This client is useful in scenarios where you can't set the system properties
because, for example, they would affect multiple clients running within the JVM.

To run this client, issue this command in another tab:

```bash
java -cp pkcs11-tls-client/target/pkcs11-tls-client-1.0-SNAPSHOT.jar \
  org.example.ProgrammaticPKCS11HttpsClient pkcs11.cfg 1234 \
  client-truststore.p12 changeit \
  https://localhost:8443/hello

Response Code: 200
Response Content: <h1>Hello Servlet</h1>session=node0ipz28v1879pv1gd3qm21mxowy4
```