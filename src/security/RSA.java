package security;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.HashMap;
import java.util.Random;

public class RSA {
    static HashMap<Character, BigInteger> publicKey;
    static HashMap<Character, BigInteger> privateKey;
    static StringBuilder sb;

    public static void main(String[] args) throws IOException {
        //키 생성
        generateKey();
        //문장 입력받기
        BigInteger original = getInputString();
        //암호화
        BigInteger c = encrypt(original);
        System.out.println("C = " + c);
        //복호화
        BigInteger p = decrypt(c);
        System.out.println("P = " + p);
        //복호화된 코드 평문 변환
        String plaintext = getPlaintext(p);
        System.out.println("Plaintext = " + plaintext);
    }

    private static BigInteger getInputString() throws IOException {
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
        String s = br.readLine();

        sb = new StringBuilder();
        for (byte b : s.getBytes()) {
            // 평문 변환할 때 세개씩 잘라야하기 때문에
            // 문자의 byte가 2자리인 경우 앞에 0을 붙여준다.
            if (b / 100 == 0) sb.append(0);
            sb.append(b);
        }

        return new BigInteger(sb.toString());
    }

    public static void generateKey() {
        publicKey = new HashMap<>();
        privateKey = new HashMap<>();

        Random r = new Random();
        int bitLength = 1024;
        int certainty = 10;
        BigInteger p = new BigInteger(bitLength / 2, certainty, r);
        BigInteger q = new BigInteger(bitLength / 2, certainty, r);
        BigInteger n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        BigInteger e = new BigInteger("17");
        BigInteger d = e.modInverse(phi);

        //공개키 저장
        publicKey.put('e', e);
        publicKey.put('n', n);
        //개인키 저장
        privateKey.put('d', d);
        privateKey.put('p', p);
        privateKey.put('q', q);

        System.out.println("Key generation");
        System.out.printf("Public key\ne = %d,\nn = %d\n", e, n);
        System.out.printf("Private key\nd = %d,\np = %d,\nq = %d\n", d, p, q);
        System.out.println("---------------------");
    }

    public static BigInteger encrypt(BigInteger m) {
        return m.modPow(publicKey.get('e'), publicKey.get('n'));
    }

    public static BigInteger decrypt(BigInteger c) {
        return c.modPow(privateKey.get('d'), publicKey.get('n'));
    }

    public static String getPlaintext(BigInteger p) {
        sb = new StringBuilder(p.toString());

        // 맨 앞글자가 두자릿수면 0을 붙여줌
        if (sb.charAt(0) != '1') {
            sb.insert(0, 0);
        }

        byte[] bytes = new byte[sb.length() / 3];
        int start = 0;
        int end = 3;
        for (int i = 0; end <= sb.length(); i++) {
            // 세개씩 잘라서 byte 배열로 저장
            bytes[i] = Byte.parseByte(sb.substring(start, end));
            start += 3;
            end+= 3;
        }

        return new String(bytes);
    }
}
