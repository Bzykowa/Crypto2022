import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.util.ArrayList;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

public class App {

    private static String pass;
    private static String mode;
    private static KeyStoreManager ks;

    /**
     * Oracle mode of operation. Function takes a set of files and encrypts them
     * using specified algorithm.
     * 
     * @param operationMode AES Encryption mode
     * @param ks            KeyStore that stores the SecretKey
     * @param files         Files to encrypt
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws IOException
     * @throws KeyStoreException
     * @throws UnrecoverableEntryException
     */
    private static void oracle(String operationMode, KeyStoreManager ks, ArrayList<String> files)
            throws InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, BadPaddingException, IllegalBlockSizeException, IOException,
            KeyStoreException, UnrecoverableEntryException {
        SecretKey sk = ks.getKey(KeyStoreManager.MAIN_KEY);

        switch (operationMode) {
            case "CBC": {
                IvParameterSpec iv = AESEncryption.generateIv();
                for (String path : files) {
                    File input = new File(path);
                    File output = new File(path + ".enc");
                    AESEncryption.encryptFileCBC(sk, iv, input, output);
                }
                AESEncryption.saveIV(iv.getIV());
                System.out.println("Files successfully encrypted.");
                // TODO Write bytes properly
                System.out.println("iv: " + Base64.getEncoder().encodeToString(iv.getIV()));
                break;
            }
            case "GCM": {
                GCMParameterSpec iv = AESEncryption.generateGCMParameter();
                for (String path : files) {
                    File input = new File(path);
                    File output = new File(path + ".enc");
                    AESEncryption.encryptFileGCM(sk, iv, input, output);
                }
                AESEncryption.saveIV(iv.getIV());
                System.out.println("Files successfully encrypted.");
                // TODO Write bytes properly
                System.out.println("iv: " + Base64.getEncoder().encodeToString(iv.getIV()));
                break;
            }
            default: {
                System.out.println("Wrong operation mode. No files were encrypted.");
            }
        }

    }

    /**
     * Challenge mode of operation. Function takes two files, randomly selects one
     * of them and encrypts it using specified algorithm.
     * 
     * @param operationMode AES encryption mode
     * @param ks            KeyStore that stores the SecretKey
     * @param m0            First file
     * @param m1            Second file
     * @throws InvalidKeyException
     * @throws NoSuchPaddingException
     * @throws NoSuchAlgorithmException
     * @throws InvalidAlgorithmParameterException
     * @throws BadPaddingException
     * @throws IllegalBlockSizeException
     * @throws IOException
     * @throws KeyStoreException
     * @throws UnrecoverableEntryException
     */
    private static void challenge(String operationMode, KeyStoreManager ks, String m0, String m1)
            throws InvalidKeyException,
            NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException, BadPaddingException,
            IllegalBlockSizeException, IOException, KeyStoreException, UnrecoverableEntryException {
        SecretKey sk = ks.getKey(KeyStoreManager.MAIN_KEY);
        SecureRandom random = new SecureRandom();
        File challenge = random.nextBoolean() ? new File(m0) : new File(m1);
        File result = new File("challenge.enc");

        switch (operationMode) {
            case "CBC": {
                IvParameterSpec iv = AESEncryption.generateIv();
                AESEncryption.encryptFileCBC(sk, iv, challenge, result);
                AESEncryption.saveIV(iv.getIV());
                System.out.println("Challenge successfully encrypted.");
                // TODO Write bytes properly
                System.out.println("iv: " + Base64.getEncoder().encodeToString(iv.getIV()));
                break;
            }
            case "GCM": {
                GCMParameterSpec iv = AESEncryption.generateGCMParameter();
                AESEncryption.encryptFileGCM(sk, iv, challenge, result);
                AESEncryption.saveIV(iv.getIV());
                System.out.println("Challenge successfully encrypted.");
                // TODO Write bytes properly
                System.out.println("iv: " + Base64.getEncoder().encodeToString(iv.getIV()));
                break;
            }
            default: {
                System.out.println("Wrong operation mode. No files were encrypted.");
            }
        }

    }

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

        System.out.println("Choose encryption mode: CBC (default) / GCM");
        BufferedReader reader = new BufferedReader(new InputStreamReader(System.in));
        String input = reader.readLine();

        switch (input) {
            case "GCM":
            case "gcm": {
                mode = "GCM";
                break;
            }
            default: {
                mode = "CBC";
            }
        }

        System.out.println("Choose the operation mode: oracle (default) / challenge");
        reader = new BufferedReader(new InputStreamReader(System.in));
        input = reader.readLine();

        switch (input) {
            case "Challenge":
            case "challenge": {
                System.out.println("Enter the first challenge file name.");
                String m0 = reader.readLine();

                System.out.println("Enter the second challenge file name.");
                String m1 = reader.readLine();

                challenge(mode, ks, m0, m1);

                break;
            }
            default: {
                ArrayList<String> filePaths = new ArrayList<>();

                System.out.println("Enter file names for the oracle to encrypt. Submit an empty line to finish.");

                input = reader.readLine();
                while (!input.isBlank()) {
                    filePaths.add(input);
                    input = reader.readLine();
                }

                oracle(mode, ks, filePaths);
                break;
            }
        }

    }
}
