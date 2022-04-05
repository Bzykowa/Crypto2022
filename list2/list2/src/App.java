import java.security.SecureRandom;
import java.math.BigInteger;

public class App {
    public static void main(String[] args) throws Exception {
        NaiveRSA rsa = new NaiveRSA(64);
        // TimingAttack ta = new TimingAttack(rsa);
        BlindSignature bs = new BlindSignature(rsa);

        // ta.genTestSets(100);
        // ta.test();

        SecureRandom random = new SecureRandom();
        long m = random.nextLong();
        BigInteger s = bs.blindSign(BigInteger.valueOf(m));
        Boolean correctSign = bs.blindVerify(BigInteger.valueOf(m), s);

        System.out.println("m: " + m);
        System.out.println("signature: " + s);
        System.out.println("Verified: " + correctSign);

    }
}
