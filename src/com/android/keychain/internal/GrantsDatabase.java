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

import android.content.ContentValues;
import android.content.Context;
import android.content.pm.PackageManager;
import android.database.Cursor;
import android.database.DatabaseUtils;
import android.database.sqlite.SQLiteDatabase;
import android.database.sqlite.SQLiteOpenHelper;
import android.util.Log;

public class GrantsDatabase {
    private static final String TAG = "KeyChain";

    private static final String DATABASE_NAME = "grants.db";
    private static final int DATABASE_VERSION = 1;
    private static final String TABLE_GRANTS = "grants";
    private static final String GRANTS_ALIAS = "alias";
    private static final String GRANTS_GRANTEE_UID = "uid";

    private static final String SELECTION_COUNT_OF_MATCHING_GRANTS =
            "SELECT COUNT(*) FROM "
                    + TABLE_GRANTS
                    + " WHERE "
                    + GRANTS_GRANTEE_UID
                    + "=? AND "
                    + GRANTS_ALIAS
                    + "=?";

    private static final String SELECT_GRANTS_BY_UID_AND_ALIAS =
            GRANTS_GRANTEE_UID + "=? AND " + GRANTS_ALIAS + "=?";

    private static final String SELECTION_GRANTS_BY_UID = GRANTS_GRANTEE_UID + "=?";

    private static final String SELECTION_GRANTS_BY_ALIAS = GRANTS_ALIAS + "=?";

    public DatabaseHelper mDatabaseHelper;

    private class DatabaseHelper extends SQLiteOpenHelper {
        public DatabaseHelper(Context context) {
            super(context, DATABASE_NAME, null /* CursorFactory */, DATABASE_VERSION);
        }

        @Override
        public void onCreate(final SQLiteDatabase db) {
            db.execSQL(
                    "CREATE TABLE "
                            + TABLE_GRANTS
                            + " (  "
                            + GRANTS_ALIAS
                            + " STRING NOT NULL,  "
                            + GRANTS_GRANTEE_UID
                            + " INTEGER NOT NULL,  "
                            + "UNIQUE ("
                            + GRANTS_ALIAS
                            + ","
                            + GRANTS_GRANTEE_UID
                            + "))");
        }

        @Override
        public void onUpgrade(final SQLiteDatabase db, int oldVersion, final int newVersion) {
            Log.e(TAG, "upgrade from version " + oldVersion + " to version " + newVersion);

            if (oldVersion == 1) {
                // the first upgrade step goes here
                oldVersion++;
            }
        }
    }

    public GrantsDatabase(Context context) {
        mDatabaseHelper = new DatabaseHelper(context);
    }

    public void destroy() {
        mDatabaseHelper.close();
        mDatabaseHelper = null;
    }

    boolean hasGrantInternal(final SQLiteDatabase db, final int uid, final String alias) {
        final long numMatches =
                DatabaseUtils.longForQuery(
                        db,
                        SELECTION_COUNT_OF_MATCHING_GRANTS,
                        new String[] {String.valueOf(uid), alias});
        return numMatches > 0;
    }

    public boolean hasGrant(final int uid, final String alias) {
        final SQLiteDatabase db = mDatabaseHelper.getWritableDatabase();
        return hasGrantInternal(db, uid, alias);
    }

    public void setGrant(final int uid, final String alias, final boolean value) {
        final SQLiteDatabase db = mDatabaseHelper.getWritableDatabase();
        if (value) {
            if (!hasGrantInternal(db, uid, alias)) {
                final ContentValues values = new ContentValues();
                values.put(GRANTS_ALIAS, alias);
                values.put(GRANTS_GRANTEE_UID, uid);
                db.insert(TABLE_GRANTS, GRANTS_ALIAS, values);
            }
        } else {
            db.delete(
                    TABLE_GRANTS,
                    SELECT_GRANTS_BY_UID_AND_ALIAS,
                    new String[] {String.valueOf(uid), alias});
        }
    }

    public void removeGrantsForAlias(String alias) {
        final SQLiteDatabase db = mDatabaseHelper.getWritableDatabase();
        db.delete(TABLE_GRANTS, SELECTION_GRANTS_BY_ALIAS, new String[] {alias});
    }

    public void removeAllGrants() {
        final SQLiteDatabase db = mDatabaseHelper.getWritableDatabase();
        db.delete(TABLE_GRANTS, null /* whereClause */, null /* whereArgs */);
    }

    public void purgeOldGrants(PackageManager pm) {
        final SQLiteDatabase db = mDatabaseHelper.getWritableDatabase();
        Cursor cursor = null;
        db.beginTransaction();
        try {
            cursor =
                    db.query(
                            TABLE_GRANTS,
                            new String[] {GRANTS_GRANTEE_UID},
                            null,
                            null,
                            GRANTS_GRANTEE_UID,
                            null,
                            null);
            while (cursor.moveToNext()) {
                final int uid = cursor.getInt(0);
                final boolean packageExists = pm.getPackagesForUid(uid) != null;
                if (packageExists) {
                    continue;
                }
                Log.d(TAG, String.format(
                        "deleting grants for UID %d because its package is no longer installed",
                        uid));
                db.delete(
                        TABLE_GRANTS,
                        SELECTION_GRANTS_BY_UID,
                        new String[] {Integer.toString(uid)});
            }
            db.setTransactionSuccessful();
        } finally {
            if (cursor != null) {
                cursor.close();
            }
            db.endTransaction();
        }
    }
}
