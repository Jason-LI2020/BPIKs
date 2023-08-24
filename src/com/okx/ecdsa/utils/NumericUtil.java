package com.okx.ecdsa.utils;

import java.math.BigInteger;
import java.util.Random;
// import com.okx.ecdsa.utils.Pocklington;


public class NumericUtil {

    private static int CERTAINTY = 100;
    public BigInteger getRandomNumber(int bitlength) { 
        Random rnd = new Random(); 
        StringBuilder sb = new StringBuilder(bitlength); 
        for(int i=0; i < bitlength; i++) sb.append((char)('0' + rnd.nextInt(2))); 
        return new BigInteger(sb.toString(), 2); 
    }

    public BigInteger getRandomWithinRange(BigInteger a) {
        BigInteger b;
        do {
            b = getRandomNumber(a.bitLength());
        } while (b.compareTo(a) >= 0);
        return b;
    }

    public BigInteger prime(int bitlength) {
        BigInteger p= getRandomNumber(bitlength);
        return p.nextProbablePrime();
    }

    public BigInteger safePrime(int bitlength) {
        BigInteger p, q;
        q = getRandomNumber(bitlength - 1);
        q = q.nextProbablePrime();
        p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);

        while (!p.isProbablePrime(CERTAINTY)) {
            do {
                q = q.nextProbablePrime();
            } while (q.mod(BigInteger.TEN).equals(BigInteger.valueOf(7)) 
                    || !q.mod(BigInteger.valueOf(4)).equals(BigInteger.valueOf(3)));
            p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
            // while (p.bitLength() != bitlength) {
            //     q = getRandomNumber(bitlength - 1);
            //     q = q.nextProbablePrime();
            //     p = q.multiply(BigInteger.TWO).add(BigInteger.ONE);
            // }
        }

        return p;
    }

    public BigInteger quadraticResidue(BigInteger a, BigInteger p) {
        BigInteger b = a.modPow(p.subtract(BigInteger.ONE).divide(BigInteger.TWO), p);
        if (b.compareTo(BigInteger.ONE) == 0) {
            return b;
        } else {
            return b.subtract(p);
        }
    }

}
