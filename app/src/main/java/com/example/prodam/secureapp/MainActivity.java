package com.example.prodam.secureapp;

import android.content.Intent;
import android.os.Build;
import android.provider.MediaStore;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.security.keystore.KeyProtection;
import android.support.v7.app.AppCompatActivity;
import android.os.Bundle;
import android.util.Base64;
import android.util.Log;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.Button;
import android.widget.EditText;
import android.widget.ListView;
import android.widget.TextView;

import org.xmlpull.v1.XmlPullParser;
import org.xmlpull.v1.XmlPullParserException;
import org.xmlpull.v1.XmlPullParserFactory;

import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.text.CollationElementIterator;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.List;

//import java.io.*;
//import java.nio.*;
import java.security.*;
import java.security.spec.*;

import static android.R.attr.data;

public class MainActivity extends AppCompatActivity {

    private TextView displayXmlContent;
    private TextView displayBoolContent;
    private XmlPullParserFactory xmlPullParserFactory;

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

        displayXmlContent = (TextView)findViewById(R.id.display_xml);
        displayBoolContent = (TextView)findViewById(R.id.display_bool);
        Button loadXmlButton = (Button)findViewById(R.id.xml_read);
        loadXmlButton.setOnClickListener(new View.OnClickListener() {
            @Override
            public void onClick(View v) {
                try {
                    xmlPullParserFactory = XmlPullParserFactory.newInstance();
                    xmlPullParserFactory.setNamespaceAware(false);
                    XmlPullParser parser = xmlPullParserFactory.newPullParser();
                    // access the xml file and convert it to input stream
                    InputStream is = returnXmlInputStream();
                    parser.setInput(is, null);
                    String returnedStringValue = getLoadedXmlValues(parser);
                    byte[] doc = returnedStringValue.getBytes();
                    byte[] docSigned = getSign(doc);
                    if (docSigned != null) {

                        String assinatura = Arrays.toString(docSigned);
                        Log.w("AVISO", assinatura);
                    }
                    boolean signed = vrfyCert(doc, docSigned);
                    String returnedSign = "" + signed;
                    displayXmlContent.setText(returnedStringValue);
                    displayBoolContent.setText(returnedSign);
                } catch (XmlPullParserException | IOException e) {
                    e.printStackTrace();
                }
            }
        });
    }

    private InputStream returnXmlInputStream() throws IOException {
        InputStream is = this.getAssets().open("parse.xml");
        return is;
    }

    private String getLoadedXmlValues(XmlPullParser parser) throws XmlPullParserException, IOException {
        int eventType = parser.getEventType();
        String name = null;
        Entity mEntity = new Entity();
        while (eventType != XmlPullParser.END_DOCUMENT){
            if(eventType == XmlPullParser.START_TAG){
                name = parser.getName();
                if(name.equals("to")){
                    mEntity.to = parser.nextText();
                }
                else if(name.equals("from")){
                    mEntity.fromm = parser.nextText();
                }
                else if(name.equals("heading")){
                    mEntity.heading = parser.nextText();
                }
                else if(name.equals("body")){
                    mEntity.body = parser.nextText();
                }
            }
            eventType = parser.next();
        }
        return mEntity.to + ", " + mEntity.fromm + ", " + mEntity.heading + ", " + mEntity.body;
    }

    public class Entity{
        public String to;
        public String fromm;
        public String heading;
        public String body;
    }

    private byte[] getSign (byte[] b) {

        KeyStore ks = null; // declaracao necessaria para usar 'entry' fora do try/if
        try {
            Log.w("AVISO", "Entrou no primeiro SIGN try");
            ks = KeyStore.getInstance("AndroidKeyStore");
            if (ks != null) {
                Log.w("AVISO", "Entrou no primeiro SIGN par tryif");
                ks.load(null);
            }
            else Log.w("AVISO", "NAO Entrou no primeiro SIGN if");
        } catch (KeyStoreException | CertificateException | NoSuchAlgorithmException | IOException e) {
            Log.w("AVISO", "entrou no CATCH do primeiro SIGN tryif");
            e.printStackTrace();
        }

        KeyStore.Entry entry = null;  // declaracao necessaria para usar 'entry' fora do try/if
        try {
            Log.w("AVISO", "Entrou no segundo SIGN try");
            if (ks != null) {
                Log.w("AVISO", "Entrou no segundo SIGN if");
                entry = ks.getEntry("NOVO_alias", null);
            }
            else Log.w("AVISO", "NAO Entrou no segundo SIGN if ... =/");
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            e.printStackTrace();
        }

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w("AVISO", "SIGN: Not an instance of a PrivateKeyEntry");
            return null; // Cannot return a value from a method with void result type
        }

        // Cria objeto assinatura
        // Cria objeto initSign (ou habilita "s" a assinar)
        try {
            Log.w("AVISO", "Entrou no terceiro SIGN try");
            Signature s = Signature.getInstance("SHA256withECDSA");
            if (s != null) {
                Log.w("AVISO", "Entrou no terceiro SIGN if");
                Log.w("AVISO", "entrou no ultimo SIGN if");
                s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
                s.update(b); // b é o arquivo a ser validado
                return s.sign(); // a funcao que assina de fato
            }
            else Log.w("AVISO", "NAO Entrou no terceiro SIGN if");
        } catch (InvalidKeyException | SignatureException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            Log.w("AVISO", "NAO Entrou no terceiro SIGN try");
        }
        Log.w("AVISO", "ULTIMO SIGN return - NAO desejado");
        return null;
    }

    private boolean vrfyCert (byte[] verifica, byte[] assinado){

        KeyStore ks = null;
        try {
            Log.w("AVISO", "Entrou no primeiro VRFY try");
            ks = KeyStore.getInstance("AndroidKeyStore");
            ks.load(null);
        } catch (KeyStoreException | IOException | NoSuchAlgorithmException | CertificateException e) {
            Log.w("AVISO", "NAO Entrou no primeiro VRFY try");
            e.printStackTrace();
        }

        KeyStore.Entry entry = null;
        try {
            Log.w("AVISO", "Entrou no segundo VRFY try");
            assert ks != null;
            entry = ks.getEntry("NOVO_alias", null);
        } catch (NoSuchAlgorithmException | KeyStoreException | UnrecoverableEntryException e) {
            Log.w("AVISO", "NAO Entrou no segundo VRFY try", e);
            e.printStackTrace();
        }

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w("AVISO", "VRFY: Not an instance of a PrivateKeyEntry");
            //return false; // verificar se o metodo vrfyCert (este metodo) deve retornar algo, como esse booleano
        }

        // Cria objeto assinatura
        try {
            Log.w("AVISO", "Entrou no terceiro VRFY try");
            Signature s = Signature.getInstance("SHA256withECDSA");
            // Cria objeto initVerify (ou habilita "s" a "verificar")
            if (entry != null){
                Log.w("AVISO", "Entrou no if do terceiro VRFY try - RETURN desejado");
                s.initVerify(((KeyStore.PrivateKeyEntry) entry).getCertificate());
                s.update(verifica);         // texto (em byte []) enviado para a funcao de assinatura
                return s.verify(assinado);  // texto (em byte []) que retornou da funcao de assinatura
            }
            else Log.w("AVISO", "NAO Entrou no if do terceiro VRFY try");
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            Log.w("AVISO", "NAO Entrou no terceiro VRFY try");
            e.printStackTrace();
        }
        Log.w("AVISO", "ULTIMO VRFY return - NAO desejado");
        return false;
    }

    /*
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

    */

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

        // kpg.initialize(new KeyGenParameterSpec.Builder( alias, KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY ).setDigests( KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512 ).build());

        // KeyPair kp = kpg.generateKeyPair();

        // desse jeito "funciona", mas pede por uma maneira de englobar o exception
        // usando extension na chamada do botao ou o try/catch
        // KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");

        // algo parecido com o item abaixo deveria funcionar tb
        // "RSA" e "AndroidKeyStore" são itens da lista Security.getProviders() - em teoria
        // kpg = KeyPairGenerator.getInstance(___, Security.getProviders(___));
        // https://developer.android.com/reference/java/security/Security.html#getProviders()

        KeyPairGenerator kpg = null;

        try {
            Log.i("AVISO", "entrou primeiro try");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                kpg = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore");
                Log.i("AVISO", "entrou primeiro if");
            }
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            Log.i("AVISO", "NAO entrou primeiro if");
        }

        try {
            Log.i("AVISO", "entrou segundo try");
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                Log.i("AVISO", "entrou primeiro-segundo if");
                if (kpg != null) {
                    kpg.initialize( new KeyGenParameterSpec.Builder( "NOVO_alias",
                             KeyProperties.PURPOSE_SIGN | KeyProperties.PURPOSE_VERIFY)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512)
                            .build() );
                    Log.i("AVISO", "entrou SEGUNDO if");
                }
            }
        } catch (InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            Log.i("AVISO", "NAO entrou SEGUNDO if");
        }

        if (kpg != null) {
            Log.i("AVISO", " entrou terceiro if");
            KeyPair kp = kpg.generateKeyPair();
            String prim = kp.getPrivate().toString();
            TextView cert = (TextView) findViewById(R.id.textView);
            cert.setText(prim);

            String secund = kp.getPublic().toString();
            TextView cert2 = (TextView) findViewById(R.id.textView2);
            cert2.setText(secund);
        }


        Log.i("AVISO", "TERMINOU BUTAO");
    }

    // https://developer.android.com/reference/android/security/keystore/KeyProtection.html
    public void importCert (View view) {

        PrivateKey privateKey = null;   // EC/RSA private key
        try {
            privateKey = PrivateKeyReader.get("fd.key");
        } catch (Exception e) {
            e.printStackTrace();
        }

        //Certificate[] certChain = ...; // Certificate chain with the first certificate
        // containing the corresponding EC/RSA public key.

        KeyStore keyStore = null;
        try {
            keyStore = KeyStore.getInstance("AndroidKeyStore");
            keyStore.load(null);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            Log.w("AVISO", "NAO Entrou no primeiro try", e);
        }

        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            if (keyStore != null) {
                try {
                    keyStore.setEntry( "key2", new KeyStore.PrivateKeyEntry(privateKey, certChain),
                            new KeyProtection.Builder(KeyProperties.PURPOSE_SIGN)
                            .setDigests(KeyProperties.DIGEST_SHA256, KeyProperties.DIGEST_SHA512).build());

                    // Key pair imported, obtain a reference to it.

                    PrivateKey keyStorePrivateKey = (PrivateKey) keyStore.getKey("key2", null);

                    PublicKey publicKey = keyStore.getCertificate("key2").getPublicKey();

                    // The original private key can now be discarded.

                } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException e) {
                    e.printStackTrace();
                }
            }
        }


        //Signature signature = Signature.getInstance("SHA256withECDSA");
        //signature.initSign(keyStorePrivateKey);


    }


    public static class PrivateKeyReader {

        public static PrivateKey get(String filename) throws Exception {

            File f = new File(filename);
            FileInputStream fis = new FileInputStream(f);
            DataInputStream dis = new DataInputStream(fis);
            byte[] keyBytes = new byte[(int)f.length()];
            dis.readFully(keyBytes);
            dis.close();

            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        }
    }

    /*

    // Signing and Verifying Data
    // Sign data by fetching the KeyStore.Entry from the keystore and using the Signature APIs, such as sign():

    public void signCert (View view) {

        Log.i("AVISO", "Assina Certificado clicado");

         // Use a PrivateKey in the KeyStore to create a signature over
         // some data


        // original code from https://developer.android.com/training/articles/keystore.html#SigningAndVerifyingData
        *//*KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
        ks.load(null);
        KeyStore.Entry entry = ks.getEntry(alias, null);
        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w(TAG, "Not an instance of a PrivateKeyEntry");
            return null;
        }
        Signature s = Signature.getInstance("SHA256withECDSA");
        s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
        s.update(data);
        byte[] signature = s.sign();*//*



        KeyStore ks = null;

        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        try {
            if (ks != null) {
                ks.load(null);
            }
        } catch (IOException | NoSuchAlgorithmException | CertificateException e) {
            e.printStackTrace();
        }

        KeyStore.Entry entry = null;

        try {
            if (ks != null) {
                entry = ks.getEntry("NOVO_alias", null);
            }
        } catch (NoSuchAlgorithmException | UnrecoverableEntryException | KeyStoreException e) {
            e.printStackTrace();
        }

        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w("AVISO", "Not an instance of a PrivateKeyEntry");
            // return null; // Cannot return a value from a method with void result type
        }

        // Cria objeto assinatura
        Signature s = null;
        try {
            s = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // Cria objeto initSign (ou habilita "s" a assinar)
        try {
            if (s != null) {
                if (entry != null) {
                    s.initSign(((KeyStore.PrivateKeyEntry) entry).getPrivateKey());
                }
            }
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        s.update(is); // data é o arquivo a ser validado

        try {
            byte[] signature = s.sign(); // a funcao que assina de fato
        } catch (SignatureException e) {
            e.printStackTrace();
        }
    }

*/
/*
    // metodo abaixo ainda está bem quebrado. como a funcao disso é verificar um cert, ele deveria receber um doc assinado...
    public void vrfyCert (View view) {

        Log.i("AVISO", "Verifica Certificado clicado");

        // Similarly, verify data with the verify(byte[]) method:


         * Verify a signature previously made by a PrivateKey in our
         * KeyStore. This uses the X.509 certificate attached to our
         * private key in the KeyStore to validate a previously
         * generated signature.
         *//*


        */
/*
        // original code from https://developer.android.com/training/articles/keystore.html#SigningAndVerifyingData
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
        *//*



        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("AndroidKeyStore");
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }

        try {
            ks.load(null);
        } catch (IOException | CertificateException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        KeyStore.Entry entry = null;
        try {
            entry = ks.getEntry("alias teste", null);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (UnrecoverableEntryException e) {
            e.printStackTrace();
        } catch (KeyStoreException e) {
            e.printStackTrace();
        }


        if (!(entry instanceof KeyStore.PrivateKeyEntry)) {
            Log.w("AVISO", "Not an instance of a PrivateKeyEntry");
            //return false; // verificar se o metodo vrfyCert (este metodo) deve retornar algo, como esse booleano
        }

        // Cria objeto assinatura
        try {
            Signature s = Signature.getInstance("SHA256withECDSA");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }

        // Cria objeto initVerify (ou habilita "s" a "verificar")
        // s.initVerify(((PrivateKeyEntry) entry).getCertificate());

        // s.update(data);

        // boolean valid = s.verify(signature);

    }
*/

}
