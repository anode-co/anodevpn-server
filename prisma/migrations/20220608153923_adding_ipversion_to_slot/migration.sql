/*
  Warnings:

  - Added the required column `ipVersion` to the `Slot` table without a default value. This is not possible if the table is not empty.

*/
-- RedefineTables
PRAGMA foreign_keys=OFF;
CREATE TABLE "new_Slot" (
    "publicKey" TEXT NOT NULL,
    "number" INTEGER NOT NULL DEFAULT 0,
    "ipVersion" TEXT NOT NULL
);
INSERT INTO "new_Slot" ("number", "publicKey") SELECT "number", "publicKey" FROM "Slot";
DROP TABLE "Slot";
ALTER TABLE "new_Slot" RENAME TO "Slot";
CREATE UNIQUE INDEX "Slot_publicKey_key" ON "Slot"("publicKey");
PRAGMA foreign_key_check;
PRAGMA foreign_keys=ON;
