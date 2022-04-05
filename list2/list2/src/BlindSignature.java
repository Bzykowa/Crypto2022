import java.math.BigInteger;
import java.security.SecureRandom;

public class BlindSignature {

    private NaiveRSA oracle;

    public BlindSignature(NaiveRSA oracle) {
        this.oracle = oracle;
    }

    /**
     * Blind signature using following arithmetic:
     * signed val = (m * r^e)
     * blinded sign = (m * r^e)^d = m^d * r
     * revealing = (m^d * r) * r_inv = m^d
     * 
     * @param m
     * @return
     */
    public BigInteger blindSign(BigInteger m) {

        BigInteger r = randCoPrime();
        BigInteger rInv = r.modInverse(oracle.getN());

        // Blind the input
        BigInteger blind = m.multiply(r.modPow(oracle.getE(), oracle.getN()));

        // Sign blinded message
        BigInteger blindSign = oracle.sign(blind);

        // Reveal the signature
        BigInteger signature = blindSign.multiply(rInv).mod(oracle.getN());

        return signature;
    }

    public Boolean blindVerify(BigInteger m, BigInteger s){
        return oracle.verify(m,s);
    }

    private BigInteger randCoPrime() {
        SecureRandom random = new SecureRandom();

        int nSize = oracle.getN().bitLength();
        int randBitSize = random.nextInt(1, nSize);
        BigInteger r = new BigInteger(randBitSize, 5, random);

        return oracle.getN().gcd(r).compareTo(BigInteger.ONE) == 0 ? r : randCoPrime();
    }

}
