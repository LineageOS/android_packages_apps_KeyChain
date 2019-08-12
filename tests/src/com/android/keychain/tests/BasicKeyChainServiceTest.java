/*
 * Copyright (C) 2019 The Android Open Source Project
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
package com.android.keychain.tests;

import static com.google.common.truth.Truth.assertThat;
import static org.junit.Assert.fail;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.os.ConditionVariable;
import android.os.IBinder;
import android.os.Process;
import android.os.RemoteException;
import android.platform.test.annotations.LargeTest;
import android.security.Credentials;
import android.security.IKeyChainService;
import android.util.Log;
import androidx.test.InstrumentationRegistry;
import androidx.test.runner.AndroidJUnit4;
import com.android.keychain.tests.support.IKeyChainServiceTestSupport;
import java.io.IOException;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import libcore.java.security.TestKeyStore;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;

@LargeTest
@RunWith(AndroidJUnit4.class)
public class BasicKeyChainServiceTest {
    private static final String TAG = "BasicKeyChainServiceTest";
    private static final String ALIAS_1 = "client";

    private Context mContext;

    private final ConditionVariable mSupportServiceAvailable = new ConditionVariable(false);
    private IKeyChainServiceTestSupport mTestSupportService;
    private boolean mIsSupportServiceBound;

    private ServiceConnection mSupportConnection =
            new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                    Log.d(TAG, "test support service connected!");
                    mTestSupportService = IKeyChainServiceTestSupport.Stub.asInterface(service);
                    mSupportServiceAvailable.open();
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                    mSupportServiceAvailable.close();
                    mTestSupportService = null;
                }
            };

    private final ConditionVariable mKeyChainAvailable = new ConditionVariable(false);
    private IKeyChainService mKeyChainService;
    private boolean mIsKeyChainServiceBound;

    private ServiceConnection mServiceConnection =
            new ServiceConnection() {
                @Override
                public void onServiceConnected(ComponentName name, IBinder service) {
                    Log.d(TAG, "KeyChain service connected!");
                    mKeyChainService = IKeyChainService.Stub.asInterface(service);
                    mKeyChainAvailable.open();
                }

                @Override
                public void onServiceDisconnected(ComponentName name) {
                    mKeyChainAvailable.close();
                    mKeyChainService = null;
                }
            };

    @Before
    public void setUp() {
        mContext = InstrumentationRegistry.getTargetContext();
        bindTestSupportService();
        assertThat(mIsSupportServiceBound).isTrue();
        bindKeyChainService();
        assertThat(mIsKeyChainServiceBound).isTrue();
    }

    @After
    public void tearDown() {
        unbindTestSupportService();
        assertThat(mIsSupportServiceBound).isFalse();
        unbindKeyChainService();
        assertThat(mIsKeyChainServiceBound).isFalse();
    }

    @Test
    public void testCanAccessKeyAfterGettingGrant()
            throws RemoteException, IOException, CertificateException {
        Log.d(TAG, "Testing access to imported key after getting grant.");
        waitForSupportService();
        waitForKeyChainService();

        assertThat(mTestSupportService.keystoreReset()).isTrue();
        installFirstKey();
        assertThat(mKeyChainService.requestPrivateKey(ALIAS_1)).isNull();
        mTestSupportService.grantAppPermission(Process.myUid(), ALIAS_1);
        assertThat(mKeyChainService.requestPrivateKey(ALIAS_1)).isNotNull();
    }

    void bindTestSupportService() {
        Intent serviceIntent = new Intent(mContext, IKeyChainServiceTestSupport.class);
        serviceIntent.setComponent(
                new ComponentName(
                        "com.android.keychain.tests.support",
                        "com.android.keychain.tests.support.KeyChainServiceTestSupport"));
        Log.d(TAG, String.format("Binding intent: %s", serviceIntent));
        mIsSupportServiceBound =
                mContext.bindService(serviceIntent, mSupportConnection, Context.BIND_AUTO_CREATE);
        Log.d(TAG, String.format("Support service binding result: %b", mIsSupportServiceBound));
    }

    void unbindTestSupportService() {
        if (mIsSupportServiceBound) {
            mContext.unbindService(mSupportConnection);
            mIsSupportServiceBound = false;
        }
    }

    void bindKeyChainService() {
        Context appContext = mContext.getApplicationContext();
        Intent intent = new Intent(IKeyChainService.class.getName());
        ComponentName comp = intent.resolveSystemService(appContext.getPackageManager(), 0);
        intent.setComponent(comp);

        Log.d(TAG, String.format("Binding to KeyChain: %s", intent));
        mIsKeyChainServiceBound =
                appContext.bindServiceAsUser(
                        intent,
                        mServiceConnection,
                        Context.BIND_AUTO_CREATE,
                        Process.myUserHandle());
        Log.d(TAG, String.format("KeyChain service binding result: %b", mIsKeyChainServiceBound));
    }

    void unbindKeyChainService() {
        if (mIsKeyChainServiceBound) {
            mContext.getApplicationContext().unbindService(mServiceConnection);
            mIsKeyChainServiceBound = false;
        }
    }

    void installFirstKey() throws RemoteException, IOException, CertificateException {
        String intermediate = "-intermediate";
        String root = "-root";

        String alias1PrivateKey = Credentials.USER_PRIVATE_KEY + ALIAS_1;
        String alias1ClientCert = Credentials.USER_CERTIFICATE + ALIAS_1;
        String alias1IntermediateCert = (Credentials.CA_CERTIFICATE + ALIAS_1 + intermediate);
        String alias1RootCert = (Credentials.CA_CERTIFICATE + ALIAS_1 + root);
        PrivateKeyEntry privateKeyEntry =
                TestKeyStore.getClientCertificate().getPrivateKey("RSA", "RSA");
        Certificate intermediate1 = privateKeyEntry.getCertificateChain()[1];
        Certificate root1 = TestKeyStore.getClientCertificate().getRootCertificate("RSA");

        assertThat(
                mTestSupportService.keystoreImportKey(
                    alias1PrivateKey, privateKeyEntry.getPrivateKey().getEncoded()))
            .isTrue();
        assertThat(
                mTestSupportService.keystorePut(
                    alias1ClientCert,
                    Credentials.convertToPem(privateKeyEntry.getCertificate())))
            .isTrue();
        assertThat(
                mTestSupportService.keystorePut(
                    alias1IntermediateCert, Credentials.convertToPem(intermediate1)))
            .isTrue();
        assertThat(
                mTestSupportService.keystorePut(alias1RootCert, Credentials.convertToPem(root1)))
            .isTrue();
    }

    void waitForSupportService() {
        Log.d(TAG, "Waiting for support service.");
        assertThat(mSupportServiceAvailable.block(10000)).isTrue();;
        assertThat(mTestSupportService).isNotNull();
    }

    void waitForKeyChainService() {
        Log.d(TAG, "Waiting for keychain service.");
        assertThat(mKeyChainAvailable.block(10000)).isTrue();;
        assertThat(mKeyChainService).isNotNull();
    }
}
