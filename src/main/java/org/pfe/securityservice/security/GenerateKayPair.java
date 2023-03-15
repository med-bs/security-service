package org.pfe.securityservice.security;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class GenerateKayPair {
    public static void main(String[] args) throws NoSuchAlgorithmException, IOException {
        KeyPairGenerator keyPairGenerator=KeyPairGenerator.getInstance("RSA");
        var keyPair=keyPairGenerator.generateKeyPair();
        byte[] pub = keyPair.getPublic().getEncoded();
        byte[] pri = keyPair.getPrivate().getEncoded();
        PemWriter pemWriterPublic = new PemWriter(new OutputStreamWriter(new FileOutputStream("src/main/resources/certifications/public.pem")));
        PemObject pemObjectPublic=new PemObject("PUBLIC KEY",pub);
        pemWriterPublic.writeObject(pemObjectPublic);
        pemWriterPublic.close();

        PemWriter pemWriterPrivate = new PemWriter(new OutputStreamWriter(new FileOutputStream("src/main/resources/certifications/private.pem")));
        PemObject pemObjectPrivate=new PemObject("PRIVATE KEY",pri);
        pemWriterPrivate.writeObject(pemObjectPrivate);
        pemWriterPrivate.close();
    }
}