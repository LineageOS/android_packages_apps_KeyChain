/*
 * Copyright (C) 2017 The Android Open Source Project
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

package com.android.keychain.internal;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import android.content.pm.PackageManager;
import com.android.keychain.TestConfig;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.RobolectricTestRunner;
import org.robolectric.RuntimeEnvironment;
import org.robolectric.annotation.Config;

/** Unit tests for {@link com.android.keychain.internal.GrantsDatabase}. */
@RunWith(RobolectricTestRunner.class)
@Config(manifest = TestConfig.MANIFEST_PATH, sdk = TestConfig.SDK_VERSION)
public final class GrantsDatabaseTest {
    private static final String DUMMY_ALIAS = "dummy_alias";
    private static final String DUMMY_ALIAS2 = "another_dummy_alias";
    private static final int DUMMY_UID = 1000;
    private static final int DUMMY_UID2 = 1001;

    private GrantsDatabase mGrantsDB;

    @Before
    public void setUp() {
        mGrantsDB = new GrantsDatabase(RuntimeEnvironment.application);
    }

    @Test
    public void testSetGrant_notMixingUIDs() {
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS, true);
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID2, DUMMY_ALIAS));
    }

    @Test
    public void testSetGrant_notMixingAliases() {
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS, true);
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS2));
    }

    @Test
    public void testSetGrantTrue() {
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS));
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS, true);
        Assert.assertTrue(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS));
    }

    @Test
    public void testSetGrantFalse() {
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS, false);
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS));
    }

    @Test
    public void testSetGrantTrueThenFalse() {
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS, true);
        Assert.assertTrue(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS));
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS, false);
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS));
    }

    @Test
    public void testRemoveAliasInformation() {
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS, true);
        mGrantsDB.setGrant(DUMMY_UID2, DUMMY_ALIAS, true);
        mGrantsDB.setIsUserSelectable(DUMMY_ALIAS, true);
        Assert.assertTrue(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS));
        mGrantsDB.removeAliasInformation(DUMMY_ALIAS);
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS));
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID2, DUMMY_ALIAS));
        Assert.assertFalse(mGrantsDB.isUserSelectable(DUMMY_ALIAS));
    }

    @Test
    public void testRemoveAllAliasesInformation() {
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS, true);
        mGrantsDB.setGrant(DUMMY_UID2, DUMMY_ALIAS, true);
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS2, true);
        mGrantsDB.setIsUserSelectable(DUMMY_ALIAS, true);
        mGrantsDB.removeAllAliasesInformation();
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS));
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID2, DUMMY_ALIAS));
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS2));
        Assert.assertFalse(mGrantsDB.isUserSelectable(DUMMY_ALIAS));
    }

    @Test
    public void testPurgeOldGrantsDoesNotDeleteGrantsForExistingPackages() {
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS, true);
        PackageManager pm = mock(PackageManager.class);
        when(pm.getPackagesForUid(DUMMY_UID)).thenReturn(new String[]{"p"});
        mGrantsDB.purgeOldGrants(pm);
        Assert.assertTrue(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS));
    }

    @Test
    public void testPurgeOldGrantsPurgesAllNonExistingPackages() {
        mGrantsDB.setGrant(DUMMY_UID, DUMMY_ALIAS, true);
        mGrantsDB.setGrant(DUMMY_UID2, DUMMY_ALIAS, true);
        PackageManager pm = mock(PackageManager.class);
        when(pm.getPackagesForUid(DUMMY_UID)).thenReturn(null);
        when(pm.getPackagesForUid(DUMMY_UID2)).thenReturn(null);
        mGrantsDB.purgeOldGrants(pm);
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID, DUMMY_ALIAS));
        Assert.assertFalse(mGrantsDB.hasGrant(DUMMY_UID2, DUMMY_ALIAS));
    }

    @Test
    public void testPurgeOldGrantsWorksOnEmptyDatabase() {
        // Check that NPE is not thrown.
        mGrantsDB.purgeOldGrants(null);
    }

    @Test
    public void testIsUserSelectable() {
        Assert.assertFalse(mGrantsDB.isUserSelectable(DUMMY_ALIAS));
        mGrantsDB.setIsUserSelectable(DUMMY_ALIAS, true);
        Assert.assertTrue(mGrantsDB.isUserSelectable(DUMMY_ALIAS));
    }

    @Test
    public void testSetUserSelectable() {
        mGrantsDB.setIsUserSelectable(DUMMY_ALIAS, true);
        Assert.assertTrue(mGrantsDB.isUserSelectable(DUMMY_ALIAS));
        mGrantsDB.setIsUserSelectable(DUMMY_ALIAS, false);
        Assert.assertFalse(mGrantsDB.isUserSelectable(DUMMY_ALIAS));
        mGrantsDB.setIsUserSelectable(DUMMY_ALIAS, true);
        Assert.assertTrue(mGrantsDB.isUserSelectable(DUMMY_ALIAS));
    }
}
