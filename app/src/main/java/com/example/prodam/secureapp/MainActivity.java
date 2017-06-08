package com.example.prodam.secureapp;

import android.content.Intent;
import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.EditText;
import android.widget.ListView;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.text.CollationElementIterator;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

public class MainActivity extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        /*
        //https://developer.android.com/reference/java/security/KeyStore.html#getEntry(java.lang.String,%20java.security.KeyStore.ProtectionParameter)
        //Before a keystore can be accessed, it must be loaded.
        KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
        // get user password and file input stream
        char[] password = getPassword();
        try (FileInputStream fis = new FileInputStream("keyStoreName")) {
            ks.load(fis, password);
        }
        //To create an empty keystore using the above load method, pass null as the InputStream argument.
        */




        KeyPair keyPair = rsa.generateKeys();

        byte[] publicKey = keyPair.getPublic().getEncoded();
        byte[] privateKey = keyPair.getPrivate().getEncoded();

        privateText.setText( Base64.encodeToString(privateKey, Base64.NO_WRAP) );
        publicText.setText( Base64.encodeToString(publicKey, Base64.NO_WRAP) );

    }

    public KeyPair generateKeys() {
        KeyPair keyPair = null;
        try {
            // get instance of rsa cipher
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(2048);            // initialize key generator
            keyPair = keyGen.generateKeyPair(); // generate pair of keys
        } catch(GeneralSecurityException e) {
            System.out.println(e);
        }
        return keyPair;
    }

    public void criaCert (View view){

        Log.i("BOTAO", "Cria Certificado clicado");

        /*
         * Generate a new EC key pair entry in the Android Keystore by
         * using the KeyPairGenerator API. The private key can only be
         * used for signing or verification and only with SHA-256 or
         * SHA-512 as the message digest.
         */

        // original command
        // KeyPairGenerator kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");

        // desse jeito "funciona", mas pede por uma maneira de englobar o exception
        // usando extension na chamada do botao ou o try/catch
        // KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

        // algo parecido com o item abaixo deveria funcionar tb
        // "RSA" e "AndroidKeyStore" são itens da lista Security.getProviders() - em teoria
        // kpg = KeyPairGenerator.getInstance(Security.getProviders()[1]);
        // https://developer.android.com/reference/java/security/Security.html#getProviders()

        KeyPairGenerator kpg = null;
        try {
            try {
                kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_RSA,"RSA");
            } catch (NoSuchProviderException e) {
                e.printStackTrace();
            }
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }


        kpg.initialize( new KeyGenParameterSpec.Builder( "alias",
                 KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                .build() );

        KeyPair kp = kpg.generateKeyPair();


    }


    // Signing and Verifying Data
    public void usaCert (View view){

        Log.i("BOTAO", "Usa Certificado clicado");



        // Sign data by fetching the KeyStore.Entry from the keystore and using the Signature APIs, such as sign():

        /*
         * Use a PrivateKey in the KeyStore to create a signature over
         * some data.
         */
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(alias, null);
        if (!(entry instanceof PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return null;
        }
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(((PrivateKeyEntry) entry).getPrivateKey());
        s.update(data);
        byte[] signature = s.sign();



        // Similarly, verify data with the verify(byte[]) method:

        /*
         * Verify a signature previously made by a PrivateKey in our
         * KeyStore. This uses the X.509 certificate attached to our
         * private key in the KeyStore to validate a previously
         * generated signature.
         */
        KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(alias, null);
        if (!(entry instanceof PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return false;
        }
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initVerify(((PrivateKeyEntry) entry).getCertificate());
        s.update(data);
        boolean valid = s.verify(signature);

    }

}
