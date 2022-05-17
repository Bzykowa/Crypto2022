import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.UnrecoverableKeyException;

public class Task2 {

    private static String pass;
    private static KeyStoreManager ks;

    public static void main(String[] args) throws Exception {

        System.out.println("Please enter the password:");

        int unsuccessfulLoginCounter = 0;
        boolean wrongPassword = true;

        while (wrongPassword) {
            try {
                BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
                pass = reader.readLine();
                ks = new KeyStoreManager("KeyStore.jceks", pass);
                wrongPassword = false;
            } catch (IOException e) {
                // Probably a wrong password if not close gracefully
                if (e.getCause() instanceof UnrecoverableKeyException && unsuccessfulLoginCounter < 3) {
                    System.out.println("Wrong password. Try again...");
                    continue;
                } else {
                    System.err.println("Unable to read from the KeyStore. Closing...");
                    System.exit(1);
                }
            }
        }

        System.out.println("How many tries for the CPA?:");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String input = reader.readLine();
        int n = Integer.valueOf(input);

        CPADistinguisher cpa = new CPADistinguisher(ks.getKey(KeyStoreManager.MAIN_KEY), AESEncryption.generateIv());
        int successful = 0;
        for (int i = 0; i < n; i++) {
            if (cpa.testCPA())
                successful++;
        }
        System.out.println("For " + n + " tests, " + successful + " were successful.");
    }

}
