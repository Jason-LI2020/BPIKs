package com.okx.ecdsa.utils;
// import com.okx.ecdsa.utils.NumericUtil;
import java.math.BigInteger;

public class PaillierBlumProof {

    public BigInteger w;
    public BigInteger[] x_arr;
    public BigInteger[] a_arr;
    public BigInteger[] b_arr;
    public BigInteger[] z_arr;

    // public BigInteger[] y_arr;


    public boolean prove(BigInteger N, BigInteger p, BigInteger q, int security){
        NumericUtil numericUtil = new NumericUtil();

        if(N.compareTo(p.multiply(q)) != 0) {return false;};

        this.w = numericUtil.getRandomNumber(N.bitLength()).mod(N);
        while(jacobi(w, N) != -1){
            this.w = numericUtil.getRandomNumber(N.bitLength()).mod(N);
        };

        String oracle = N.toString(16)  + this.w.toString(16);
        
        BigInteger[] y_arr = new BigInteger[security];
        BigInteger p_inv = p.modInverse(q);
        BigInteger q_inv = q.modInverse(p);
        BigInteger phi = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        BigInteger pow = N.modInverse(phi);

        this.x_arr = new BigInteger[security];
        this.a_arr = new BigInteger[security];
        this.b_arr = new BigInteger[security];
        this.z_arr = new BigInteger[security];
        // this.y_arr = new BigInteger[security];

        for (int i = 0; i < security; i++) {
            // TODO: to be relaced by FS scheme
            String rnd = HashUtil.getSHA( oracle + 4*i, "SHA-512") + HashUtil.getSHA( oracle + 4*i + 1, "SHA-512") + HashUtil.getSHA( oracle + 4*i + 2, "SHA-512") + HashUtil.getSHA( oracle + 4*i + 3, "SHA-512");
            y_arr[i] = new BigInteger(rnd, 16).mod(N);
            BigInteger[] result = getQuaticSqrt(N, p, q, p_inv, q_inv, w, y_arr[i]);
            this.x_arr[i] = result[0];
            this.a_arr[i] = result[1];
            this.b_arr[i] = result[2];
            this.z_arr[i] = y_arr[i].modPow(pow, N);
        }

        return true;
    }

    public boolean verify(BigInteger N) {
        // assert (N is an odd composite number)
        if (N.mod(BigInteger.TWO).compareTo(BigInteger.ZERO) == 0 || N.isProbablePrime(100)) {
            System.out.println("N should be an odd composite number");
            return false;
        }

        if (this.a_arr.length == 0 || this.a_arr.length != this.b_arr.length || this.a_arr.length != this.z_arr.length || this.a_arr.length != this.x_arr.length) {
            System.out.println("invalid proof length");
            return false;
        }

        BigInteger[] y_arr = new BigInteger[this.a_arr.length];

        for (int i = 0; i < this.a_arr.length; i++) {
            String oracle = N.toString(16)  + this.w.toString(16);
            String rnd = HashUtil.getSHA( oracle + 4*i, "SHA-512") + HashUtil.getSHA( oracle + 4*i + 1, "SHA-512") + HashUtil.getSHA( oracle + 4*i + 2, "SHA-512") + HashUtil.getSHA( oracle + 4*i + 3, "SHA-512");
            y_arr[i] = new BigInteger(rnd, 16).mod(N);
            // y_arr[i] = new BigInteger(HashUtil.getSHA( oracle + i, "SHA-512"), 16).modPow(BigInteger.valueOf(4),N);
        
            // assert (z^N = r mod N)
            if (z_arr[i].modPow(N, N).compareTo(y_arr[i]) != 0) {
                System.out.println("z^N != r mod N");
                return false;
            }

            // c = (-1)^a * w^b * r mod N
            // assert (x^4 = c mod N)
            BigInteger c = BigInteger.ONE.negate().modPow(a_arr[i], N).multiply(w.modPow(b_arr[i], N)).multiply(y_arr[i]).mod(N);
            // System.out.println("c:"+c);
            if (x_arr[i].modPow(BigInteger.valueOf(4), N).compareTo(c) != 0) {
                System.out.println("x^4 != (-1)^a * w^b * r mod N");
                return false;
            }
        }
    
        System.out.println("verify success");
        return true;
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


    public BigInteger[] getQuaticSqrt(BigInteger N, BigInteger p, BigInteger q, BigInteger p_inv, BigInteger q_inv, BigInteger w, BigInteger r) {
        Pocklington pocklington = new Pocklington();
        NumericUtil numericUtil = new NumericUtil();

        boolean flag_1 = false;
        boolean flag_2 = false;
        BigInteger quadratic_root_1 = BigInteger.ZERO;
        BigInteger quadratic_root_2 = BigInteger.ZERO;
        BigInteger a = BigInteger.ZERO;
        BigInteger b = BigInteger.ZERO;
        BigInteger root = BigInteger.ZERO;

        BigInteger[] result = {BigInteger.ZERO, BigInteger.ZERO, BigInteger.ZERO};

        // y' = (-1)^a * w^b * r
        // one of {r, -1 * r, w * r, -1 * w * r} is a quadratic residue
        BigInteger[] r_arr = new BigInteger[4];
        r_arr[0] = r;
        r_arr[1] = r.multiply(BigInteger.ONE.negate());
        r_arr[2] = r.multiply(this.w);
        r_arr[3] = r.multiply(this.w).multiply(BigInteger.ONE.negate());

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
