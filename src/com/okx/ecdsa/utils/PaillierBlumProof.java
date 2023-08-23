package com.okx.ecdsa.utils;
// import com.okx.ecdsa.utils.NumericUtil;
import java.math.BigInteger;

public class PaillierBlumProof {
    NumericUtil numericUtil = new NumericUtil();

    public boolean prove(BigInteger N, BigInteger p, BigInteger q, int security){
        if(N.compareTo(p.multiply(q)) != 0) {return false;};

        BigInteger w = getJacobi(p, q);
        BigInteger[] y_arr = new BigInteger[security];
        BigInteger[] x_arr = new BigInteger[security];
        BigInteger[] a_arr = new BigInteger[security];
        BigInteger[] b_arr = new BigInteger[security];
        for (int i = 0; i < security; i++) {
            // TODO: to be relaced by FS scheme
            y_arr[i] = numericUtil.getRandomNumber(N.toString(2).length()).mod(N);
        }





        return true;
    }

    public BigInteger getJacobi(BigInteger p, BigInteger q) {
        BigInteger N = p.multiply(q);
        BigInteger w = numericUtil.getRandomNumber(N.toString(2).length()).mod(N);
        do {
            BigInteger a = numericUtil.quadraticResidue(w, p);
            BigInteger b = numericUtil.quadraticResidue(w, q);
            BigInteger c = a.multiply(b);
            if (c.compareTo(BigInteger.ONE.negate()) == 0) {
                return w;
            }
            w = numericUtil.getRandomNumber(N.toString(2).length()).mod(N);
        } while (true);

    }
    
    // https://en.wikipedia.org/wiki/Jacobi_symbol#Calculating_the_Jacobi_symbol
    public int jacobi(BigInteger a, BigInteger n) {
        if (n.compareTo(BigInteger.ZERO) == -1 || n.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0) {
            System.out.println("jacobi error: n should be positive and odd");
            return 0;
        }

        a = a.mod(n);
        int t = 1;
        BigInteger r;

        while (a.compareTo(BigInteger.ZERO) != 0) {
            while (a.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0) {
                a = a.divide(BigInteger.TWO);
                r = n.mod(BigInteger.valueOf(8));
                if (r.compareTo(BigInteger.valueOf(3)) == 0 || r.compareTo(BigInteger.valueOf(5)) == 0) {
                    t = -t;
                }
            }
            r = n;
            n = a;
            a = r;
            if (a.mod(BigInteger.valueOf(4)).compareTo(BigInteger.valueOf(3)) == 0 && n.mod(BigInteger.valueOf(4)).compareTo(BigInteger.valueOf(3)) == 0) {
                t = -t;
            }
            a = a.mod(n);
        }

        if (n.compareTo(BigInteger.ONE) == 0) {
            return t;
        } else {
            return 0;
        }


    }


    public BigInteger[] getQuaticSqrt(BigInteger N, BigInteger p, BigInteger q, BigInteger p_inv, BigInteger q_inv, BigInteger w, BigInteger r, BigInteger root, BigInteger a, BigInteger b) {
        Pocklington pocklington = new Pocklington();
        BigInteger a1;
        BigInteger b1;
        boolean flag_1 = false;
        boolean flag_2 = false;
        BigInteger quadratic_root_1 = BigInteger.ZERO;
        BigInteger quadratic_root_2 = BigInteger.ZERO;

        BigInteger[] result = {BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO};

        // y' = (-1)^a * w^b * r
        // one of {r, -1 * r, w * r, -1 * w * r} is a quadratic residue
        BigInteger[] r_arr = new BigInteger[4];
        r_arr[0] = r;
        r_arr[1] = r.multiply(BigInteger.ONE.negate());
        r_arr[2] = r.multiply(w);
        r_arr[3] = r.multiply(w).multiply(BigInteger.ONE.negate());

        // System.out.println("r_arr:"+r_arr[0] + " " + r_arr[1] + " " + r_arr[2] + " " + r_arr[3]);

        BigInteger[] a1_arr = new BigInteger[4];
        BigInteger[] a2_arr = new BigInteger[4];
        for(int i = 0; i < 4; i++) {
            a1_arr[i] = r_arr[i].mod(p);
            a2_arr[i] = r_arr[i].mod(q);
        }
        // System.out.println("a1_arr:"+a1_arr[0] + " " + a1_arr[1] + " " + a1_arr[2] + " " + a1_arr[3]);
        // System.out.println("a2_arr:"+a2_arr[0] + " " + a2_arr[1] + " " + a2_arr[2] + " " + a2_arr[3]);

        for(int i = 0; i < 4; i++) {
            flag_1 = numericUtil.quadraticResidue(a1_arr[i], p).compareTo(BigInteger.ONE) == 0;
            // System.out.println("flag_1:"+flag_1);
            if (!flag_1) continue;

            flag_2 = numericUtil.quadraticResidue(a2_arr[i], q).compareTo(BigInteger.ONE) == 0;
            // System.out.println("flag_2:"+flag_2);

            if (!flag_2) continue;

            quadratic_root_1 = pocklington.sqrt(a1_arr[i], p);
            quadratic_root_2 = pocklington.sqrt(a2_arr[i], q);

            a = ((i & 0x01) > 0)? BigInteger.ONE : BigInteger.ZERO;
            b = ((i & 0x02) > 0)? BigInteger.ONE : BigInteger.ZERO;
            break;

        }
        // System.out.println("flag_2:"+flag_2);
        if(!flag_2) return result;

        a1_arr[0] = quadratic_root_1;
        a1_arr[1] = quadratic_root_1.multiply(BigInteger.ONE.negate());
        a1_arr[2] = quadratic_root_1;
        a1_arr[3] = quadratic_root_1.multiply(BigInteger.ONE.negate());

        a2_arr[0] = quadratic_root_2;
        a2_arr[1] = quadratic_root_2;
        a2_arr[2] = quadratic_root_2.multiply(BigInteger.ONE.negate());
        a2_arr[3] = quadratic_root_2.multiply(BigInteger.ONE.negate());

        for (int i = 0; i < 4; i++) {
            flag_1 = numericUtil.quadraticResidue(a1_arr[i], p).compareTo(BigInteger.ONE) == 0;
            if (!flag_1) continue;
            flag_2 = numericUtil.quadraticResidue(a2_arr[i], q).compareTo(BigInteger.ONE) == 0;
            if (!flag_2) continue;

            quadratic_root_1 = pocklington.sqrt(a1_arr[i], p);
            quadratic_root_2 = pocklington.sqrt(a2_arr[i], q);

            root = quadratic_root_1.multiply(q_inv).multiply(q).add(quadratic_root_2.multiply(p_inv).multiply(p)).mod(N);

            result[0] = root;
            result[1] = a;
            result[2] = b;
            return result;
        }

        return result;

    }
}
