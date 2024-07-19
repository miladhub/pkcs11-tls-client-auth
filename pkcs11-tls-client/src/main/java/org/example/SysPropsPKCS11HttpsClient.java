package org.example;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.Provider;
import java.security.Security;

public class SysPropsPKCS11HttpsClient
{
    public static void main(String[] args)
    throws Exception {
        if (args.length != 2) {
            System.err.println(
                    """
                    Args:
                    - PKCS#11 conf file
                    - server URL
                    """);
            System.exit(1);
        }

        String pkcs11conf = args[0];
        String serverUrl = args[1];

        Provider pkcs11Provider = Security.getProvider("SunPKCS11");
        pkcs11Provider = pkcs11Provider.configure(pkcs11conf);
        Security.addProvider(pkcs11Provider);

        URL url = new URL(serverUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();

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
