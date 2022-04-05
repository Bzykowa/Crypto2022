import java.math.BigInteger;
import java.security.SecureRandom;

public class NaiveRSA {
    private BigInteger N;
    private BigInteger p;
    private BigInteger q;
    private BigInteger e;
    private BigInteger d;

    private int reductions = 0;
    private int h = 0;

    public NaiveRSA(int size) {
        genModulus(size);
        BigInteger m = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = (BigInteger.TWO).pow(16).add(BigInteger.ONE);
        d = e.modInverse(m);
    }

    public BigInteger getN() {
        return N;
    }

    public BigInteger getE() {
        return e;
    }

    public int getH() {
        return h;
    }

    public int getReductions() {
        return reductions;
    }

    public String getDBinary() {
        return d.toString(2);
    }

    private void genModulus(int size) {
        SecureRandom random = new SecureRandom();
        p = new BigInteger(size, 30, random);
        q = new BigInteger(size, 30, random);
        N = p.multiply(q);
    }

    private BigInteger modReduce(BigInteger a, BigInteger b) {

        if (!(a.compareTo(b) == -1)) {
            a = a.mod(b);
            reductions++;
        }
        return a;
    }

    private BigInteger fastPow(BigInteger c, BigInteger N, BigInteger d) {
        String dBin = d.toString(2);
        int dLen = dBin.length();
        reductions = 0;
        h = 0;
        BigInteger x = c;

        for (int i = 1; i < dLen; i++) {
            x = modReduce(x.pow(2), N);
            if (dBin.charAt(i) == '1') {
                x = modReduce(x.multiply(c), N);
                h++;
            }
        }

        return x;
    }

    public BigInteger enc(BigInteger x) {
        return fastPow(x, N, e);
    }

    public BigInteger dec(BigInteger c) {
        return fastPow(c, N, d);
    }

    public BigInteger sign(BigInteger m) {
        return m.modPow(d, N);
    }

    public Boolean verify(BigInteger m, BigInteger s) {
        return m.compareTo(s.modPow(e, N)) == 0;
    }
}
