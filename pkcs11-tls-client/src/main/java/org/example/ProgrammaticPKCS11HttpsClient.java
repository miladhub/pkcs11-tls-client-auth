package org.example;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.file.Files;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;

public class ProgrammaticPKCS11HttpsClient
{
    public static void main(String[] args)
    throws Exception {
        if (args.length != 5) {
            System.err.println(
                    """
                    Args:
                    - PKCS#11 conf file
                    - PKCS#11 pin
                    - PKCS#12 trust store
                    - PKCS#12 trust store password
                    - server URL
                    """);
            System.exit(1);
        }

        String pkcs11conf = args[0];
        String pin = args[1];
        String pkcs12path = args[2];
        String password = args[3];
        String serverUrl = args[4];

        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        pkcs11Provider = pkcs11Provider.configure(pkcs11conf);
        Security.addProvider(pkcs11Provider);

        KeyStore pkcs11ks = KeyStore.getInstance("PKCS11", pkcs11Provider);
        pkcs11ks.load(null, pin.toCharArray());

        KeyManagerFactory kmf =
                KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(pkcs11ks, null);

        KeyStore pkcs12ks;
        try (InputStream is = Files.newInputStream(new File(pkcs12path).toPath())
        ) {
            pkcs12ks = KeyStore.getInstance("PKCS12");
            pkcs12ks.load(is, password.toCharArray());
        }

        TrustManagerFactory tmf =
                TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(pkcs12ks);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        URL url = new URL(serverUrl);
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.setSSLSocketFactory(sslContext.getSocketFactory());

        int responseCode = conn.getResponseCode();
        System.out.println("Response Code: " + responseCode);

        try (
                BufferedReader in =
                        new BufferedReader(new InputStreamReader(conn.getInputStream()))
        ) {
            String inputLine;
            StringBuilder content = new StringBuilder();
            while ((inputLine = in.readLine()) != null) {
                content.append(inputLine);
            }
            System.out.println("Response Content: " + content);
        }
    }

}
