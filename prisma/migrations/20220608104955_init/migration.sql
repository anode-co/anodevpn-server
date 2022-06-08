-- CreateTable
CREATE TABLE "Lease" (
    "publicKey" TEXT NOT NULL,
    "ipv4NumSlots" INTEGER NOT NULL DEFAULT 0,
    "ipv6NumSlots" INTEGER NOT NULL DEFAULT 0,
    "expiration" DATETIME NOT NULL
);

-- CreateTable
CREATE TABLE "Slot" (
    "publicKey" TEXT NOT NULL,
    "number" INTEGER NOT NULL DEFAULT 0
);

-- CreateIndex
CREATE UNIQUE INDEX "Lease_publicKey_key" ON "Lease"("publicKey");

-- CreateIndex
CREATE UNIQUE INDEX "Slot_publicKey_key" ON "Slot"("publicKey");
