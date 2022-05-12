import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

/**
 * A class responsible for managing the app's KeyStore.
 */
public class KeyStoreManager {
    private KeyStore ks;
    private String ksPath;
    private String password;

    public static final String MAIN_KEY = "main_key";

    /**
     * Main class constructor
     * 
     * @param ksPath   Path to the KeyStore file
     * @param password Password to unlock the KeyStore
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws KeyStoreException
     */
    public KeyStoreManager(String ksPath, String password)
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {
        this.ksPath = ksPath;
        this.password = password;
        initializeKeyStore();
    }

    /**
     * Load existing KeyStore or create one.
     * 
     * @throws KeyStoreException
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     */
    private void initializeKeyStore()
            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException {

        char[] pwdArray = password.toCharArray();

        try {
            ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(ksPath), pwdArray);
        } catch (FileNotFoundException e) {
            // KeyStore doesn't exist so create one
            ks.load(null, pwdArray);
            SecretKey sk = AESEncryption.generateKey(AESEncryption.DEFAULT_KEY_LENGTH);
            saveKey(MAIN_KEY, sk);
        }
    }

    /**
     * Save a symmetric key to the KeyStore
     * 
     * @param alias Identifier of the key
     * @param key   Key to save in the KeyStore
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws CertificateException
     * @throws FileNotFoundException
     * @throws IOException
     */
    public void saveKey(String alias, SecretKey key) throws KeyStoreException, NoSuchAlgorithmException,
            CertificateException, FileNotFoundException, IOException {
        char[] pwdArray = password.toCharArray();
        KeyStore.SecretKeyEntry secret = new KeyStore.SecretKeyEntry(key);
        KeyStore.ProtectionParameter pass = new KeyStore.PasswordProtection(pwdArray);
        ks.setEntry(alias, secret, pass);
        ks.store(new FileOutputStream(ksPath), pwdArray);
    }

    /**
     * Read a key entry form the KeyStore
     * 
     * @param alias Key identifier
     * @return A Key corresponding to submitted alias
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     * @throws UnrecoverableEntryException
     */
    public SecretKey getKey(String alias)
            throws KeyStoreException, NoSuchAlgorithmException, UnrecoverableEntryException {
        KeyStore.SecretKeyEntry secretKeyEnt = (KeyStore.SecretKeyEntry) ks.getEntry(alias,
                new KeyStore.PasswordProtection(password.toCharArray()));
        return secretKeyEnt.getSecretKey();
    }

}
