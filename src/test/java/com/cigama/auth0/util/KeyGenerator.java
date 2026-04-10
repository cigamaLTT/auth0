package com.cigama.auth0.util;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.util.Base64;

public class KeyGenerator {

    public static void main(String[] args) throws Exception {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }

        KeyPairGenerator rsaGen = KeyPairGenerator.getInstance("RSA");
        rsaGen.initialize(2048);
        KeyPair rsaPair = rsaGen.generateKeyPair();
        
        System.out.println("JWT_RSA_PRIVATE_KEY=" + Base64.getEncoder().encodeToString(rsaPair.getPrivate().getEncoded()));
        System.out.println("JWT_RSA_PUBLIC_KEY=" + Base64.getEncoder().encodeToString(rsaPair.getPublic().getEncoded()));

        KeyPairGenerator mlDsaGen = KeyPairGenerator.getInstance("ML-DSA", "BC");
        KeyPair mlDsaPair = mlDsaGen.generateKeyPair();
        
        System.out.println("JWT_MLDSA_PRIVATE_KEY=" + Base64.getEncoder().encodeToString(mlDsaPair.getPrivate().getEncoded()));
        System.out.println("JWT_MLDSA_PUBLIC_KEY=" + Base64.getEncoder().encodeToString(mlDsaPair.getPublic().getEncoded()));
    }
}
