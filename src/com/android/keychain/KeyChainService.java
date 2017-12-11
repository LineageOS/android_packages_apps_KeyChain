/*
 * Copyright (C) 2011 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.android.keychain;

import android.app.BroadcastOptions;
import android.app.IntentService;
import android.content.ContentValues;
import android.content.Context;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.content.pm.StringParceledListSlice;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.os.Binder;
import android.os.Build;
import android.os.IBinder;
import android.os.Process;
import android.os.UserHandle;
import android.security.Credentials;
import android.security.IKeyChainService;
import android.security.KeyChain;
import android.security.keymaster.KeymasterArguments;
import android.security.keymaster.KeymasterCertificateChain;
import android.security.keymaster.KeymasterDefs;
import android.security.KeyStore;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.ParcelableKeyGenParameterSpec;
import android.text.TextUtils;
import android.util.Log;
import com.android.keychain.internal.GrantsDatabase;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.Collections;

import com.android.org.conscrypt.TrustedCertificateStore;

public class KeyChainService extends IntentService {

    private static final String TAG = "KeyChain";

    /** created in onCreate(), closed in onDestroy() */
    public GrantsDatabase mGrantsDb;

    public KeyChainService() {
        super(KeyChainService.class.getSimpleName());
    }

    @Override public void onCreate() {
        super.onCreate();
        mGrantsDb = new GrantsDatabase(this);
    }

    @Override
    public void onDestroy() {
        super.onDestroy();
        mGrantsDb.destroy();
        mGrantsDb = null;
    }

    private final IKeyChainService.Stub mIKeyChainService = new IKeyChainService.Stub() {
        private final KeyStore mKeyStore = KeyStore.getInstance();
        private final TrustedCertificateStore mTrustedCertificateStore
                = new TrustedCertificateStore();

        @Override
        public String requestPrivateKey(String alias) {
            checkArgs(alias);

            final String keystoreAlias = Credentials.USER_PRIVATE_KEY + alias;
            final int uid = Binder.getCallingUid();
            return mKeyStore.grant(keystoreAlias, uid);
        }

        @Override public byte[] getCertificate(String alias) {
            checkArgs(alias);
            return mKeyStore.get(Credentials.USER_CERTIFICATE + alias);
        }

        @Override public byte[] getCaCertificates(String alias) {
            checkArgs(alias);
            return mKeyStore.get(Credentials.CA_CERTIFICATE + alias);
        }

        @Override public boolean isUserSelectable(String alias) {
            validateAlias(alias);
            return mGrantsDb.isUserSelectable(alias);
        }

        @Override public void setUserSelectable(String alias, boolean isUserSelectable) {
            validateAlias(alias);
            checkSystemCaller();
            mGrantsDb.setIsUserSelectable(alias, isUserSelectable);
        }

        @Override public boolean generateKeyPair(
                String algorithm, ParcelableKeyGenParameterSpec parcelableSpec) {
            checkSystemCaller();
            final KeyGenParameterSpec spec = parcelableSpec.getSpec();
            final String alias = spec.getKeystoreAlias();
            // Validate the alias here to avoid relying on KeyGenParameterSpec c'tor preventing
            // the creation of a KeyGenParameterSpec instance with a non-empty alias.
            if (TextUtils.isEmpty(alias) || spec.getUid() != KeyStore.UID_SELF) {
                Log.e(TAG, "Cannot generate key pair with empty alias or specified uid.");
                return false;
            }

            if (spec.getAttestationChallenge() != null) {
                Log.e(TAG, "Key generation request should not include an Attestation challenge.");
                return false;
            }

            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance(
                        algorithm, "AndroidKeyStore");
                // Do not prepend USER_PRIVATE_KEY to the alias because
                // AndroidKeyStoreKeyPairGeneratorSpi will helpfully prepend that in
                // generateKeyPair.
                generator.initialize(spec);
                KeyPair kp = generator.generateKeyPair();
                if (kp == null) {
                    Log.e(TAG, "Key generation failed.");
                    return false;
                }
                return true;
            } catch (NoSuchAlgorithmException e) {
                Log.e(TAG, "Invalid algorithm requested", e);
            } catch (InvalidAlgorithmParameterException e) {
                Log.e(TAG, "Invalid algorithm params", e);
            } catch (NoSuchProviderException e) {
                Log.e(TAG, "Could not find Keystore.", e);
            }

            return false;
        }

        @Override public boolean attestKey(
                String alias, byte[] attestationChallenge,
                KeymasterCertificateChain attestationChain) {
            checkSystemCaller();
            validateAlias(alias);

            if (attestationChallenge == null) {
                Log.e(TAG, String.format("Missing attestation challenge for alias %s", alias));
                return false;
            }

            KeymasterArguments attestArgs = new KeymasterArguments();
            attestArgs.addBytes(KeymasterDefs.KM_TAG_ATTESTATION_CHALLENGE, attestationChallenge);
            final String keystoreAlias = Credentials.USER_PRIVATE_KEY + alias;
            final int errorCode = mKeyStore.attestKey(keystoreAlias, attestArgs, attestationChain);
            return errorCode == KeyStore.NO_ERROR;
        }

        @Override public boolean setKeyPairCertificate(String alias, byte[] userCertificate,
                byte[] userCertificateChain) {
            checkSystemCaller();
            if (!mKeyStore.isUnlocked()) {
                Log.e(TAG, "Keystore is " + mKeyStore.state().toString() + ". Credentials cannot"
                        + " be installed until device is unlocked");
                return false;
            }

            if (!mKeyStore.put(Credentials.USER_CERTIFICATE + alias, userCertificate,
                        KeyStore.UID_SELF, KeyStore.FLAG_NONE)) {
                Log.e(TAG, "Failed to import user certificate " + userCertificate);
                return false;
            }

            if (userCertificateChain != null && userCertificateChain.length > 0) {
                if (!mKeyStore.put(Credentials.CA_CERTIFICATE + alias, userCertificateChain,
                            KeyStore.UID_SELF, KeyStore.FLAG_NONE)) {
                    Log.e(TAG, "Failed to import certificate chain" + userCertificateChain);
                    if (!mKeyStore.delete(Credentials.USER_CERTIFICATE + alias)) {
                        Log.e(TAG, "Failed to clean up key chain after certificate chain"
                                + " importing failed");
                    }
                    return false;
                }
            } else {
                if (!mKeyStore.delete(Credentials.CA_CERTIFICATE + alias)) {
                    Log.e(TAG, "Failed to remove CA certificate chain for alias " + alias);
                }
            }
            broadcastKeychainChange();
            broadcastLegacyStorageChange();
            return true;
        }

        private void validateAlias(String alias) {
            if (alias == null) {
                throw new NullPointerException("alias == null");
            }
        }

        private void validateKeyStoreState() {
            if (!mKeyStore.isUnlocked()) {
                throw new IllegalStateException("keystore is "
                        + mKeyStore.state().toString());
            }
        }

        private void checkArgs(String alias) {
            validateAlias(alias);
            validateKeyStoreState();

            final int callingUid = getCallingUid();
            if (!mGrantsDb.hasGrant(callingUid, alias)) {
                throw new IllegalStateException("uid " + callingUid
                        + " doesn't have permission to access the requested alias");
            }
        }

        @Override public String installCaCertificate(byte[] caCertificate) {
            checkCertInstallerOrSystemCaller();
            final String alias;
            try {
                final X509Certificate cert = parseCertificate(caCertificate);
                synchronized (mTrustedCertificateStore) {
                    mTrustedCertificateStore.installCertificate(cert);
                    alias = mTrustedCertificateStore.getCertificateAlias(cert);
                }
            } catch (IOException e) {
                throw new IllegalStateException(e);
            } catch (CertificateException e) {
                throw new IllegalStateException(e);
            }
            broadcastLegacyStorageChange();
            broadcastTrustStoreChange();
            return alias;
        }

        /**
         * Install a key pair to the keystore.
         *
         * @param privateKey The private key associated with the client certificate
         * @param userCertificate The client certificate to be installed
         * @param userCertificateChain The rest of the chain for the client certificate
         * @param alias The alias under which the key pair is installed
         * @return Whether the operation succeeded or not.
         */
        @Override public boolean installKeyPair(byte[] privateKey, byte[] userCertificate,
                byte[] userCertificateChain, String alias) {
            checkCertInstallerOrSystemCaller();
            if (!mKeyStore.isUnlocked()) {
                Log.e(TAG, "Keystore is " + mKeyStore.state().toString() + ". Credentials cannot"
                        + " be installed until device is unlocked");
                return false;
            }
            if (!removeKeyPair(alias)) {
                return false;
            }
            if (!mKeyStore.importKey(Credentials.USER_PRIVATE_KEY + alias, privateKey, -1,
                    KeyStore.FLAG_ENCRYPTED)) {
                Log.e(TAG, "Failed to import private key " + alias);
                return false;
            }
            if (!mKeyStore.put(Credentials.USER_CERTIFICATE + alias, userCertificate, -1,
                    KeyStore.FLAG_ENCRYPTED)) {
                Log.e(TAG, "Failed to import user certificate " + userCertificate);
                if (!mKeyStore.delete(Credentials.USER_PRIVATE_KEY + alias)) {
                    Log.e(TAG, "Failed to delete private key after certificate importing failed");
                }
                return false;
            }
            if (userCertificateChain != null && userCertificateChain.length > 0) {
                if (!mKeyStore.put(Credentials.CA_CERTIFICATE + alias, userCertificateChain, -1,
                        KeyStore.FLAG_ENCRYPTED)) {
                    Log.e(TAG, "Failed to import certificate chain" + userCertificateChain);
                    if (!removeKeyPair(alias)) {
                        Log.e(TAG, "Failed to clean up key chain after certificate chain"
                                + " importing failed");
                    }
                    return false;
                }
            }
            broadcastKeychainChange();
            broadcastLegacyStorageChange();
            return true;
        }

        @Override public boolean removeKeyPair(String alias) {
            checkCertInstallerOrSystemCaller();
            if (!Credentials.deleteAllTypesForAlias(mKeyStore, alias)) {
                return false;
            }
            mGrantsDb.removeAliasInformation(alias);
            broadcastKeychainChange();
            broadcastLegacyStorageChange();
            return true;
        }

        private X509Certificate parseCertificate(byte[] bytes) throws CertificateException {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(bytes));
        }

        @Override public boolean reset() {
            // only Settings should be able to reset
            checkSystemCaller();
            mGrantsDb.removeAllAliasesInformation();
            boolean ok = true;
            synchronized (mTrustedCertificateStore) {
                // delete user-installed CA certs
                for (String alias : mTrustedCertificateStore.aliases()) {
                    if (TrustedCertificateStore.isUser(alias)) {
                        if (!deleteCertificateEntry(alias)) {
                            ok = false;
                        }
                    }
                }
            }
            broadcastTrustStoreChange();
            broadcastKeychainChange();
            broadcastLegacyStorageChange();
            return ok;
        }

        @Override public boolean deleteCaCertificate(String alias) {
            // only Settings should be able to delete
            checkSystemCaller();
            boolean ok = true;
            synchronized (mTrustedCertificateStore) {
                ok = deleteCertificateEntry(alias);
            }
            broadcastTrustStoreChange();
            broadcastLegacyStorageChange();
            return ok;
        }

        private boolean deleteCertificateEntry(String alias) {
            try {
                mTrustedCertificateStore.deleteCertificateEntry(alias);
                return true;
            } catch (IOException e) {
                Log.w(TAG, "Problem removing CA certificate " + alias, e);
                return false;
            } catch (CertificateException e) {
                Log.w(TAG, "Problem removing CA certificate " + alias, e);
                return false;
            }
        }

        private void checkCertInstallerOrSystemCaller() {
            String actual = checkCaller("com.android.certinstaller");
            if (actual == null) {
                return;
            }
            checkSystemCaller();
        }
        private void checkSystemCaller() {
            String actual = checkCaller("android.uid.system:1000");
            if (actual != null) {
                throw new IllegalStateException(actual);
            }
        }
        /**
         * Returns null if actually caller is expected, otherwise return bad package to report
         */
        private String checkCaller(String expectedPackage) {
            String actualPackage = getPackageManager().getNameForUid(getCallingUid());
            return (!expectedPackage.equals(actualPackage)) ? actualPackage : null;
        }

        @Override public boolean hasGrant(int uid, String alias) {
            checkSystemCaller();
            return mGrantsDb.hasGrant(uid, alias);
        }

        @Override public void setGrant(int uid, String alias, boolean value) {
            checkSystemCaller();
            mGrantsDb.setGrant(uid, alias, value);
            broadcastPermissionChange(uid, alias, value);
            broadcastLegacyStorageChange();
        }

        @Override
        public StringParceledListSlice getUserCaAliases() {
            synchronized (mTrustedCertificateStore) {
                return new StringParceledListSlice(new ArrayList<String>(
                        mTrustedCertificateStore.userAliases()));
            }
        }

        @Override
        public StringParceledListSlice getSystemCaAliases() {
            synchronized (mTrustedCertificateStore) {
                return new StringParceledListSlice(new ArrayList<String>(
                        mTrustedCertificateStore.allSystemAliases()));
            }
        }

        @Override
        public boolean containsCaAlias(String alias) {
            return mTrustedCertificateStore.containsAlias(alias);
        }

        @Override
        public byte[] getEncodedCaCertificate(String alias, boolean includeDeletedSystem) {
            synchronized (mTrustedCertificateStore) {
                X509Certificate certificate = (X509Certificate) mTrustedCertificateStore
                        .getCertificate(alias, includeDeletedSystem);
                if (certificate == null) {
                    Log.w(TAG, "Could not find CA certificate " + alias);
                    return null;
                }
                try {
                    return certificate.getEncoded();
                } catch (CertificateEncodingException e) {
                    Log.w(TAG, "Error while encoding CA certificate " + alias);
                    return null;
                }
            }
        }

        @Override
        public List<String> getCaCertificateChainAliases(String rootAlias,
                boolean includeDeletedSystem) {
            synchronized (mTrustedCertificateStore) {
                X509Certificate root = (X509Certificate) mTrustedCertificateStore.getCertificate(
                        rootAlias, includeDeletedSystem);
                try {
                    List<X509Certificate> chain = mTrustedCertificateStore.getCertificateChain(
                            root);
                    List<String> aliases = new ArrayList<String>(chain.size());
                    final int n = chain.size();
                    for (int i = 0; i < n; ++i) {
                        String alias = mTrustedCertificateStore.getCertificateAlias(chain.get(i),
                                true);
                        if (alias != null) {
                            aliases.add(alias);
                        }
                    }
                    return aliases;
                } catch (CertificateException e) {
                    Log.w(TAG, "Error retrieving cert chain for root " + rootAlias);
                    return Collections.emptyList();
                }
            }
        }
    };

    @Override public IBinder onBind(Intent intent) {
        if (IKeyChainService.class.getName().equals(intent.getAction())) {
            return mIKeyChainService;
        }
        return null;
    }

    @Override
    protected void onHandleIntent(final Intent intent) {
        if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())) {
            mGrantsDb.purgeOldGrants(getPackageManager());
        }
    }

    private void broadcastLegacyStorageChange() {
        Intent intent = new Intent(KeyChain.ACTION_STORAGE_CHANGED);
        BroadcastOptions opts = BroadcastOptions.makeBasic();
        opts.setMaxManifestReceiverApiLevel(Build.VERSION_CODES.N_MR1);
        sendBroadcastAsUser(intent, UserHandle.of(UserHandle.myUserId()), null, opts.toBundle());
    }

    private void broadcastKeychainChange() {
        Intent intent = new Intent(KeyChain.ACTION_KEYCHAIN_CHANGED);
        sendBroadcastAsUser(intent, UserHandle.of(UserHandle.myUserId()));
    }

    private void broadcastTrustStoreChange() {
        Intent intent = new Intent(KeyChain.ACTION_TRUST_STORE_CHANGED);
        sendBroadcastAsUser(intent, UserHandle.of(UserHandle.myUserId()));
    }

    private void broadcastPermissionChange(int uid, String alias, boolean access) {
        // Since the permission change only impacts one uid only send to that uid's packages.
        final PackageManager packageManager = getPackageManager();
        String[] packages = packageManager.getPackagesForUid(uid);
        if (packages == null) {
            return;
        }
        for (String pckg : packages) {
            Intent intent = new Intent(KeyChain.ACTION_KEY_ACCESS_CHANGED);
            intent.putExtra(KeyChain.EXTRA_KEY_ALIAS, alias);
            intent.putExtra(KeyChain.EXTRA_KEY_ACCESSIBLE, access);
            intent.setPackage(pckg);
            sendBroadcastAsUser(intent, UserHandle.of(UserHandle.myUserId()));
        }
    }
}
