package com.reactnativeiocryptofastlogin;

import android.os.Build;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyInfo;
import android.security.keystore.KeyProperties;
import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.RequiresApi;
import androidx.biometric.BiometricPrompt;
import androidx.fragment.app.FragmentActivity;

import com.facebook.react.bridge.Promise;
import com.facebook.react.bridge.ReactApplicationContext;
import com.facebook.react.bridge.ReactContextBaseJavaModule;
import com.facebook.react.bridge.ReactMethod;
import com.facebook.react.bridge.UiThreadUtil;
import com.facebook.react.module.annotations.ReactModule;

import org.jetbrains.annotations.NotNull;

import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.concurrent.Executors;

@ReactModule(name = IoCryptoFastLoginModule.NAME)
public class IoCryptoFastLoginModule extends ReactContextBaseJavaModule {

  public static final String NAME = "IoCryptoFastLogin";
  private static final String FAST_LOGIN_KEY = "fast-login-key";
  private static final String DUMMY_KEY_ALIAS = "dummy-key";

  public IoCryptoFastLoginModule(ReactApplicationContext reactContext) {
    super(reactContext);
  }

  @Override
  @NonNull
  public String getName() {
    return NAME;
  }

  @ReactMethod
  public void isOneTouchLoginSupported(@NonNull Promise promise) {
    promise.resolve(isOneTouchLoginSupported(FAST_LOGIN_KEY));
  }

  private boolean isOneTouchLoginSupported(String alias) {
    // if the we have a current key already, the fast login is supported
    if (getOneTouchKey(alias) != null) {
      return true;
    }
    // otherwise, try to create a dummy hardware backed key
    PublicKey pk = createOneTouchKey(DUMMY_KEY_ALIAS, true);
    return pk != null;
  }

  @ReactMethod
  public void isOneTouchKeyAvailable(@NonNull Promise promise) {
    promise.resolve(isOneTouchKeyAvailable(FAST_LOGIN_KEY));
  }

  private boolean isOneTouchKeyAvailable(String alias) {
    return getOneTouchKey(alias) != null;
  }

  @ReactMethod
  public void getOneTouchKey(@NonNull Promise promise) {
    promise.resolve(getOneTouchKey(FAST_LOGIN_KEY));
  }

  private PublicKey getOneTouchKey(String alias) {
    try {
      KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
      ks.load(null);
      if (ks.containsAlias(alias)) {
        return ks.getCertificate(alias).getPublicKey();
      }
    } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
      Log.e(NAME, Log.getStackTraceString(e));
    }
    return null;
  }

  public void createOneTouchKey(@NonNull Promise promise) {
    promise.resolve(createOneTouchKey(FAST_LOGIN_KEY, false));
  }

  private PublicKey createOneTouchKey(String alias, boolean cleanUp) {
    // attempt to retrieve the current public key, if available
    PublicKey pk = getOneTouchKey(alias);
    // if it is available, just return it
    if (pk != null) {
      return pk;
    }
    // else create it, if on the right APILevel
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
      // generate the keypair
      try {
        KeyPair kp = getKeyPair(alias);
        Log.d(NAME, String.format("A key named %s has been created", alias));
        // get info about the generated key
        KeyInfo ki = KeyFactory
          .getInstance("RSA", "AndroidKeyStore")
          .getKeySpec(kp.getPrivate(), KeyInfo.class);
        // is the key inside a TEE or a SecureElement?
        boolean keyIsHardwareBacked = ki.isInsideSecureHardware();
        Log.d(NAME, String.format("%s key is hardware backed: %b", alias, keyIsHardwareBacked));
        if (cleanUp || !keyIsHardwareBacked) {
          // always try to clean up if key is not hardware backed
          deleteOneTouchKey(alias);
        }
        // return the public key, if key is hardware backed
        if (keyIsHardwareBacked) {
          return kp.getPublic();
        }
        // else return null, key is not hardware backed
        return null;
      } catch (NoSuchProviderException | NoSuchAlgorithmException |
        InvalidAlgorithmParameterException | InvalidKeySpecException e) {
        Log.e(NAME, Log.getStackTraceString(e));
        return null;
      }
    }
    // we are not on the right API Level
    return null;
  }

  @ReactMethod
  public void deleteOneTouchKey(@NonNull Promise promise) {
    deleteOneTouchKey(FAST_LOGIN_KEY);
  }

  private void deleteOneTouchKey(String alias) {
    try {
      KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
      ks.load(null); // before using KeyStore, it must be loaded
      ks.deleteEntry(alias);
      Log.d(NAME, String.format("A key named %s has been deleted", alias));
    } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e) {
      Log.e(NAME, Log.getStackTraceString(e));
    }
  }

  @RequiresApi(api = Build.VERSION_CODES.M)
  private KeyPair getKeyPair(String alias)
    throws NoSuchProviderException, NoSuchAlgorithmException, InvalidAlgorithmParameterException {
    int DEFAULT_RSA_KEY_SIZE = 2048; // let's use 2048 bit RSA keys
    // initialize a keypair generator
    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "AndroidKeyStore");
    kpg.initialize(new KeyGenParameterSpec
      .Builder(alias, KeyProperties.PURPOSE_SIGN) // we want a key that is used for a signature op.
      .setAlgorithmParameterSpec(
        // F4 means RSA public exponent of 65537
        new RSAKeyGenParameterSpec(DEFAULT_RSA_KEY_SIZE, RSAKeyGenParameterSpec.F4)
      )
      .setDigests(KeyProperties.DIGEST_SHA256)
      // We don't know if setting this to KeyProperties.SIGNATURE_PADDING_RSA_PKCS1
      // will enable more keys to be hardware backed on older phones
      .setSignaturePaddings(KeyProperties.SIGNATURE_PADDING_RSA_PSS)
      //  From the docs:
      // Key can only be generated if secure lock screen is set up
      //  At least on biometric mode must be enrolled
      //  Each use of the key requires a biometric authentication
      //  If lock screen is disabled, key is lost
      //  If lock screen is reset, key is lost
      //  New biometric credentials, key is lost
      //  If those requirements are not met, exception is thrown
      .setUserAuthenticationRequired(true)
      .build());
    Log.d(NAME, "A KeyPairGenerator has been initialized");
    // return the actual keypair
    return kpg.generateKeyPair();
  }

  @ReactMethod
  public void signWithOneTouchKey(byte[] data, @NonNull Promise promise) {
    signWithOneTouchKey(data, FAST_LOGIN_KEY, promise);
  }

  private void signWithOneTouchKey(byte[] data, String alias, Promise promise) {

    class PromiseCallback implements Runnable {

      private final Promise promise;
      private final byte[] data;

      private PromiseCallback(byte[] data, Promise promise) {
        this.data = data;
        this.promise = promise;
      }

      @Override
      public void run() {
        try {
          KeyStore ks = KeyStore.getInstance("AndroidKeyStore");
          ks.load(null);
          KeyStore.PrivateKeyEntry entry = (KeyStore.PrivateKeyEntry) ks.getEntry(alias, null);
          // ask for a SHA256 RSA/PSS digital signature
          Signature signature = Signature.getInstance("SHA256withRSA/PSS");
          signature.initSign(entry.getPrivateKey());
          signature.update(this.data);
          // create a CryptObject, protected by a BiometricPrompt
          BiometricPrompt.CryptoObject cryptoObject = new BiometricPrompt.CryptoObject(signature);
          // check for null of getCurrentActivity()
          if (getCurrentActivity() == null) {
            Log.d(NAME, "getCurrentActivity is null");
            // bail out
            if (promise != null) {
              promise.resolve(null);
            }
          }
          // create the BiometricPrompt with the callbacks
          BiometricPrompt biometricPrompt = new BiometricPrompt(
            (FragmentActivity) getCurrentActivity(),
            Executors.newSingleThreadExecutor(),
            new BiometricPrompt.AuthenticationCallback() {
              @Override
              public void onAuthenticationError(int errorCode, @NonNull @NotNull CharSequence errString) {
                super.onAuthenticationError(errorCode, errString);
                Log.d(NAME, "Authentication error");
                // too many failures, return null
                if (promise != null) {
                  promise.resolve(null);
                }
              }

              @Override
              public void onAuthenticationSucceeded(@NonNull @NotNull BiometricPrompt.AuthenticationResult result) {
                super.onAuthenticationSucceeded(result);
                Log.d(NAME, "Authentication succeeded");
                BiometricPrompt.CryptoObject cryptoObject = result.getCryptoObject();
                try {
                  if (cryptoObject != null && cryptoObject.getSignature() != null) {
                    byte[] signature = cryptoObject.getSignature().sign();
                    String bas64EncodedSignature = Base64.encodeToString(signature, Base64.DEFAULT);
                    Log.d(NAME, "Signature operation succeeded");
                    if (promise != null) {
                      promise.resolve(bas64EncodedSignature);
                    } else {
                      // useful when called locally (promise is null)
                      Log.d(NAME, String.format("Signature is: %s", bas64EncodedSignature));
                    }
                  }
                // something went wrong with null values of signature or cryptoObj
                  Log.d(NAME, "Signature operation failed with null values");
                  if (promise != null) {
                    promise.resolve(null);
                  }
                } catch (SignatureException e) {
                  Log.e(NAME, Log.getStackTraceString(e));
                  // return null
                  if (promise != null) {
                    promise.resolve(null);
                  }
                }
              }

              @Override
              public void onAuthenticationFailed() {
                super.onAuthenticationFailed();
                Log.d(NAME, "Authentication failed");
                // do nothing, user may try again
              }
            }
          );
          // some friendly information for the user
          BiometricPrompt.PromptInfo promptInfo = new BiometricPrompt.PromptInfo.Builder()
            .setNegativeButtonText("Cancel")
            .setTitle("Whatever")
            .build();
          // ask to authenticate
          biometricPrompt.authenticate(promptInfo, cryptoObject);
        } catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException |
          UnrecoverableEntryException | InvalidKeyException | SignatureException e) {
          Log.e(NAME, Log.getStackTraceString(e));
          // return null to RN, if you have a promise
          if (promise != null) {
            // return null
            promise.resolve(null);
          }
        }
      }
    }
    // if we have an available key...
    if (isOneTouchKeyAvailable(alias)) {
      // run it on the UI Thread to show the biometric dialog
      UiThreadUtil.runOnUiThread(new PromiseCallback(data, promise));
    }
  }

  // Example method
  // See https://reactnative.dev/docs/native-modules-android
  @ReactMethod
  public void run_android_code(Promise promise) {
    Log.d(NAME, "Native entrypoint hit");
    Log.d(NAME, String.format("isOneTouchLoginSupported(): %b", isOneTouchLoginSupported(FAST_LOGIN_KEY)));
    Log.d(NAME, String.format("isOneTouchKeyAvailable(): %b", isOneTouchKeyAvailable(FAST_LOGIN_KEY)));
    Log.d(NAME, String.format("createOneTouchKey(): %s", createOneTouchKey(FAST_LOGIN_KEY, false)));
    Log.d(NAME, String.format("isOneTouchKeyAvailable(): %b", isOneTouchKeyAvailable(FAST_LOGIN_KEY)));
    byte[] test = new byte[]{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x7F};
    Log.d(NAME, "signWithOneTouchKey(): void");
    signWithOneTouchKey(test, FAST_LOGIN_KEY, null);
  }
}
