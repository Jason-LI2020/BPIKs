package com.okx.ecdsa.utils;

import java.math.BigInteger;
import java.util.Random;


// 
// https://asecuritysite.com/zero/ped
// p = 2 * p' + 1, q = 2 * q' + 1, p',q' are primes
// n = p * q
// t = random(1, p)
// lambda = random(1, p)
// s = t ^ lambda
// commit(m) = t^m * s^r (mod n)
public class Pedersen {
    private BigInteger p;
    private BigInteger q;
    public BigInteger n;

    // s = t^lambda, which lambda is a secret
    private BigInteger t;
    private BigInteger s;
    static BigInteger security = new BigInteger("100");

    public BigInteger getRandomNumber(int bitlength) { 
        Random rnd = new Random(); 
        StringBuilder sb = new StringBuilder(bitlength); 
        for(int i=0; i < bitlength; i++) sb.append((char)('0' + rnd.nextInt(2))); 
        return new BigInteger(sb.toString(), 2); 
    } 

    public void setup(int security){
        BigInteger _p = getRandomNumber(security-1);
        BigInteger _q = getRandomNumber(security-1);
        _p = _p.nextProbablePrime();
        _q = _q.nextProbablePrime();
        this.p = BigInteger.TWO.multiply(_p).add(BigInteger.ONE);
        this.q = BigInteger.TWO.multiply(_q).add(BigInteger.ONE);
        this.n = p.multiply(q);

        this.t = getRandomNumber(security);
        BigInteger lambda = getRandomNumber(security);

        this.s = t.modPow(lambda, n);

        return;
    }

    public BigInteger commit(BigInteger x, BigInteger r){
        BigInteger c = t.modPow(x, n).multiply(s.modPow(r,n)).mod(n);
        return c;
    }

    public boolean open(BigInteger x, BigInteger r, BigInteger c) {
        boolean result = false;
        BigInteger res = t.modPow(x, n).multiply(s.modPow(r,n)).mod(n);
        System.out.println("res:"+res);
        System.out.println("c:"+c);

        if (res.compareTo(c) == 0){
            result = true;
        }
        return result;
    }

    public BigInteger add(BigInteger c1, BigInteger c2) {
        return c1.multiply(c2).mod(n);
    }
}
