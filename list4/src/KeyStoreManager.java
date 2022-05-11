import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;

import javax.crypto.SecretKey;

/**
 * A class responsible for managing the app's KeyStore.
 */
public class KeyStoreManager {
    private KeyStore ks;
    private String ksPath;
    private String password;

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
            ks = KeyStore.getInstance("JKS");
            ks.load(new FileInputStream(ksPath), pwdArray);
        } catch (FileNotFoundException e) {
            // KeyStore doesn't exist so create one
            ks.load(null, pwdArray);
            // TODO create a symmetric key
            // saveKey(alias, key);

        }
    }

   /**
    * Save a symmetric key to the KeyStore
    * @param alias Identifier of the key
    * @param key Key to save in the KeyStore
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
     * @param alias Key identifier
     * @return A Key corresponding to submitted alias
     * @throws UnrecoverableKeyException
     * @throws KeyStoreException
     * @throws NoSuchAlgorithmException
     */
    public Key getKey(String alias) throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException {
        return ks.getKey(alias, password.toCharArray());
    }

}
