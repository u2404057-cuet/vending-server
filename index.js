import express, { json } from "express";
import cors from "cors";
import dotenv from "dotenv";
import { randomUUID } from "crypto";
import { MongoClient, ObjectId, ServerApiVersion } from "mongodb";
import { fromNodeHeaders } from "better-auth/node";
import { auth } from "./lib/auth.js";

dotenv.config();
const app = express();
const port = process.env.PORT;

app.use(json({ limit: "5mb" })); // product photos arrive as base64 data URLs — default 100kb limit would reject real images
app.use(cors());

const uri = process.env.MONGO_URI;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

async function run() {
  try {
    await client.connect();
    await client.db("admin").command({ ping: 1 });
    console.log(
      "Pinged your deployment. You successfully connected to MongoDB!"
    );
  } finally {
    // Ensures that the client will close when you finish/error
    // await client.close();
  }
}
run().catch(console.dir);

async function requireAuth(req, res, next) {
  const result = await auth.api.getSession({
    headers: fromNodeHeaders(req.headers),
  });
  if (!result) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  req.user = { id: result.user.id, role: result.user.role };
  next();
}

function requireRole(allowedRoles) {
  return (req, res, next) => {
    if (!allowedRoles.includes(req.user.role)) {
      return res
        .status(403)
        .json({ error: "Forbidden: Insufficient permissions" });
    }
    next();
  };
}

app.get("/api/whoami", requireAuth, (req, res) => {
  res.json(req.user);
});

const productsCollection = client.db("dispo").collection("products");
const devicesCollection = client.db("dispo").collection("devices");
const userCollection = client.db("dispo").collection("user");
const sessionCollection = client.db("dispo").collection("session");
const accountCollection = client.db("dispo").collection("account");
const ordersCollection = client.db("dispo").collection("orders");
const ALLOWED_ROLES = ["customer", "owner", "admin"];
const ALLOWED_DEVICE_TYPES = ["coffee_machine", "vending_machine", "juice_machine"];

// ── Users (admin only) ─────────────────────────────────
app.get("/api/users", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const users = await userCollection
      .find({}, { projection: { name: 1, email: 1, role: 1, phone: 1, createdAt: 1 } })
      .toArray();
    res.json(users);
  } catch (error) {
    console.error("Error listing users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.patch("/api/users/:id/role", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const { role } = req.body;
    if (!ALLOWED_ROLES.includes(role)) {
      return res.status(400).json({ error: `role must be one of: ${ALLOWED_ROLES.join(", ")}` });
    }
    const result = await userCollection.updateOne(
      { _id: new ObjectId(req.params.id) },
      { $set: { role } }
    );
    if (result.matchedCount === 0) return res.status(404).json({ error: "User not found" });
    res.json({ success: true });
  } catch (error) {
    console.error("Error updating user role:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Permanent deletion, admin-only. Also cleans up the user's better-auth
// session/account records directly (we're bypassing better-auth's own API
// here since this is an admin acting on someone else's account), so no
// orphaned auth data is left sitting in the database. Devices/products/
// orders the user is connected to are deliberately left alone — cascading
// those deletes would be far more destructive than this feature asked for.
app.delete("/api/users/:id", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    if (req.params.id === req.user.id) {
      return res.status(400).json({ error: "You can't delete your own account." });
    }
    const user = await userCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!user) return res.status(404).json({ error: "User not found" });

    await userCollection.deleteOne({ _id: user._id });
    await sessionCollection.deleteMany({ userId: user._id.toString() });
    await accountCollection.deleteMany({ userId: user._id.toString() });

    res.json({ success: true });
  } catch (error) {
    console.error("Error deleting user:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Devices ──────────────────────────────────────────────────────
// A device starts life "unclaimed": admin provisions a blank stub — just a
// permanent qrToken, no name/slots/owner yet — matching a real vending
// machine that ships from the factory with its QR code already printed on
// it. An owner later scans that same QR code to "claim" it: that's the
// moment name/slotCount/ownerId actually get set. The qrToken itself never
// changes across this whole lifecycle, so the physical sticker stays valid
// forever.

// Admin-only: mint a new blank device stub. Type and slot count are set
// here, up front, since a real physical machine's slot layout is fixed at
// manufacture time — the owner just gets shown this later, not asked to
// invent a number themselves. Normally generates a random token, but
// accepts an optional 'token' in the body so a real physical device that
// already shipped with its own ID (burned in by the manufacturer) can be
// registered under that exact ID instead of a mismatched random one.
// `confirmedAt` stays null until the ESP32 confirms (over Bluetooth) that
// it actually received and stored this token as its own device ID — the
// QR code isn't shown to the admin until that happens (see the
// provision-status route below). A custom-token device is assumed to
// already have its ID burned in some other way, so it's marked confirmed
// immediately and skips that step entirely.
app.post("/api/devices/provision", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const customToken = req.body?.token?.trim();
    let qrToken = customToken || randomUUID();

    if (customToken) {
      const existing = await devicesCollection.findOne({ qrToken: customToken });
      if (existing) {
        return res.status(400).json({ error: "That token is already in use by another device." });
      }
    }

    const { deviceType, slotCount } = req.body || {};
    if (!ALLOWED_DEVICE_TYPES.includes(deviceType)) {
      return res.status(400).json({ error: `deviceType must be one of: ${ALLOWED_DEVICE_TYPES.join(", ")}` });
    }
    const parsedSlotCount = Number(slotCount);
    if (!Number.isInteger(parsedSlotCount) || parsedSlotCount < 1) {
      return res.status(400).json({ error: "Validation Error: 'slotCount' must be a positive integer" });
    }

    const newDevice = {
      qrToken,
      deviceType,
      slotCount: parsedSlotCount,
      name: null,
      ownerId: null,
      status: null, // becomes "active" once claimed
      createdAt: new Date(),
      claimedAt: null,
      confirmedAt: customToken ? new Date() : null,
    };
    const result = await devicesCollection.insertOne(newDevice);
    res.status(201).json({ _id: result.insertedId, ...newDevice });
  } catch (error) {
    console.error("Error provisioning device:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Admin-only: called once the admin's browser confirms (via a Bluetooth
// notification from the ESP32) that the board actually received and
// stored its qrToken as its own device ID. This is what unlocks showing
// the printable QR code for a freshly-provisioned device.
app.patch("/api/devices/:id/provision-status", requireAuth, requireRole(["admin"]), async (req, res) => {
  try {
    const device = await devicesCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!device) return res.status(404).json({ error: "Device not found" });
    await devicesCollection.updateOne({ _id: device._id }, { $set: { confirmedAt: new Date() } });
    res.json({ success: true });
  } catch (error) {
    console.error("Error confirming device provisioning:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Owner claims a previously-provisioned device by scanning its QR code —
// this is the first time it gets a name and an owner. Slot count is
// already set (by admin, at provisioning time) and only shown here, not
// asked for — though an explicit slotCount in the body is still honored,
// for backward compatibility with any device provisioned before this
// field existed.
app.post("/api/devices/:id/claim", requireAuth, requireRole(["owner", "admin"]), async (req, res) => {
  try {
    const device = await devicesCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!device) return res.status(404).json({ error: "Device not found" });
    if (device.ownerId) {
      return res.status(400).json({ error: "This device has already been claimed." });
    }

    const { name, slotCount } = req.body;
    if (!name || name.trim() === "") {
      return res.status(400).json({ error: "Validation Error: 'name' is required" });
    }

    let parsedSlotCount = device.slotCount;
    if (slotCount !== undefined) {
      parsedSlotCount = Number(slotCount);
    }
    if (!Number.isInteger(parsedSlotCount) || parsedSlotCount < 1) {
      return res.status(400).json({ error: "Validation Error: this device has no slot count set — contact the admin" });
    }

    await devicesCollection.updateOne(
      { _id: device._id },
      {
        $set: {
          name: name.trim(),
          slotCount: parsedSlotCount,
          ownerId: req.user.id,
          status: "active",
          claimedAt: new Date(),
        },
      }
    );
    const updated = await devicesCollection.findOne({ _id: device._id });
    res.json(updated);
  } catch (error) {
    console.error("Error claiming device:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Owner's own devices (or every device, for admin) — includes unclaimed
// stubs when the caller is admin, since that's how the admin device-
// management page shows what's ready to be handed to an owner.
app.get("/api/devices", requireAuth, requireRole(["owner", "admin"]), async (req, res) => {
  try {
    const filter = req.user.role === "admin" ? {} : { ownerId: req.user.id };
    const devices = await devicesCollection.find(filter).toArray();
    res.json(devices);
  } catch (error) {
    console.error("Error listing devices:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Public lookup — this is what a scanned QR code resolves through, for
// both the customer browsing flow and the owner claiming flow, before
// either of them has necessarily done anything yet.
app.get("/api/devices/by-token/:token", async (req, res) => {
  try {
    const device = await devicesCollection.findOne({ qrToken: req.params.token });
    if (!device) return res.status(404).json({ error: "Device not found" });
    res.json(device);
  } catch (error) {
    console.error("Error resolving device token:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Public, minimal list for the manual "pick your machine" dropdown —
// deliberately excludes ownerId/qrToken, and only ever lists claimed,
// active devices (an unclaimed stub or a deliberately deactivated machine
// has nothing a customer should be able to pick).
app.get("/api/devices/public", async (req, res) => {
  try {
    const devices = await devicesCollection
      .find({ status: "active" }, { projection: { name: 1 } })
      .toArray();
    res.json(devices);
  } catch (error) {
    console.error("Error listing public devices:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Owner can rename, change slot count, or toggle active/inactive on a
// device they already claimed. qrToken itself is never editable here —
// see the note above on why it must stay permanent.
app.put("/api/devices/:id", requireAuth, requireRole(["owner", "admin"]), async (req, res) => {
  try {
    const device = await devicesCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!device) return res.status(404).json({ error: "Not found" });
    if (device.ownerId !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not your device" });
    }

    const update = {};

    if (req.body.name !== undefined) {
      if (!req.body.name || req.body.name.trim() === "") {
        return res.status(400).json({ error: "Validation Error: 'name' can't be empty" });
      }
      update.name = req.body.name.trim();
    }

    if (req.body.status !== undefined) {
      if (!["active", "inactive"].includes(req.body.status)) {
        return res.status(400).json({ error: "Validation Error: status must be 'active' or 'inactive'" });
      }
      update.status = req.body.status;
    }

    if (req.body.slotCount !== undefined) {
      const parsedSlotCount = Number(req.body.slotCount);
      if (!Number.isInteger(parsedSlotCount) || parsedSlotCount < 1) {
        return res.status(400).json({ error: "Validation Error: 'slotCount' must be a positive integer" });
      }
      const highestUsedSlot = await productsCollection
        .find({ deviceId: device._id.toString() })
        .sort({ slotNumber: -1 })
        .limit(1)
        .toArray();
      if (highestUsedSlot.length > 0 && parsedSlotCount < highestUsedSlot[0].slotNumber) {
        return res.status(400).json({
          error: `Can't reduce to ${parsedSlotCount} slots — a product is already using slot ${highestUsedSlot[0].slotNumber}. Reassign or remove it first.`,
        });
      }
      update.slotCount = parsedSlotCount;
    }

    if (Object.keys(update).length === 0) {
      return res.status(400).json({ error: "Validation Error: nothing to update" });
    }

    await devicesCollection.updateOne({ _id: device._id }, { $set: update });
    const updated = await devicesCollection.findOne({ _id: device._id });
    res.json(updated);
  } catch (error) {
    console.error("Error updating device:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.delete("/api/devices/:id", requireAuth, requireRole(["owner", "admin"]), async (req, res) => {
  try {
    const device = await devicesCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!device) return res.status(404).json({ error: "Not found" });
    if (device.ownerId !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not your device" });
    }
    const productCount = await productsCollection.countDocuments({ deviceId: device._id.toString() });
    if (productCount > 0) {
      return res.status(400).json({
        error: `Can't delete — ${productCount} product(s) are still assigned to this device. Reassign or delete them first.`,
      });
    }
    await devicesCollection.deleteOne({ _id: device._id });
    res.json({ success: true });
  } catch (error) {
    console.error("Error deleting device:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Recorded by the owner-facing WiFi provisioning page (BLE feature) once
// the physical board actually confirms it joined a network. This is how
// /owner/devices shows real, verified WiFi status instead of a guess.
app.patch("/api/devices/:id/wifi-status", requireAuth, requireRole(["owner", "admin"]), async (req, res) => {
  try {
    const device = await devicesCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!device) return res.status(404).json({ error: "Not found" });
    if (device.ownerId !== req.user.id && req.user.role !== "admin") {
      return res.status(403).json({ error: "Not your device" });
    }
    const { ip } = req.body;
    if (!ip) {
      return res.status(400).json({ error: "Validation Error: 'ip' is required" });
    }
    await devicesCollection.updateOne(
      { _id: device._id },
      { $set: { lastKnownIp: ip, wifiConfiguredAt: new Date() } }
    );
    res.json({ success: true });
  } catch (error) {
    console.error("Error recording device WiFi status:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// ── Products ─────────────────────────────────────────────────────
app.get(
  "/api/products",
  async (req, res) => {
    const filter = req.query.deviceId ? { deviceId: req.query.deviceId } : {};
    const products = await productsCollection.find(filter).toArray();
    res.json(products);
  }
);

// Single product lookup — public, same as the list endpoint, since this
// backs the customer-facing product detail page.
app.get("/api/products/:id", async (req, res) => {
  try {
    const product = await productsCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!product) return res.status(404).json({ error: "Product not found" });
    res.json(product);
  } catch (error) {
    console.error("Error fetching product:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Shared by POST and PUT — a product's slot must be within the device's
// real slot count, and no other product on that same device may already
// occupy it (one physical slot holds exactly one product).
async function validateSlot(deviceId, slotNumber, excludeProductId) {
  const device = await devicesCollection.findOne({ _id: new ObjectId(deviceId) });
  if (!device) return "Validation Error: device not found";
  if (!device.slotCount) return "Validation Error: this device hasn't been claimed/configured yet";
  if (!Number.isInteger(slotNumber) || slotNumber < 1 || slotNumber > device.slotCount) {
    return `Validation Error: 'slotNumber' must be between 1 and ${device.slotCount} for this device`;
  }
  const conflictFilter = { deviceId, slotNumber };
  if (excludeProductId) conflictFilter._id = { $ne: new ObjectId(excludeProductId) };
  const conflict = await productsCollection.findOne(conflictFilter);
  if (conflict) return `Slot ${slotNumber} is already used by "${conflict.name}" on this device`;
  return null;
}

app.post(
  "/api/products",
  requireAuth,
  requireRole(["owner", "admin"]),
  async (req, res) => {
    try {
      const { name, description, price, stock, deviceId, image, slotNumber } = req.body;
      if (!name || name.trim() === "") {
        return res
          .status(400)
          .json({ error: "Validation Error: 'name' is required" });
      }

      if (!deviceId) {
        return res
          .status(400)
          .json({ error: "Validation Error: 'deviceId' is required" });
      }
      const device = await devicesCollection.findOne({ _id: new ObjectId(deviceId) });
      if (!device) {
        return res.status(400).json({ error: "Validation Error: device not found" });
      }
      if (device.ownerId !== req.user.id && req.user.role !== "admin") {
        return res.status(403).json({ error: "You don't own that device" });
      }

      const parsedSlotNumber = Number(slotNumber);
      const slotError = await validateSlot(deviceId, parsedSlotNumber, null);
      if (slotError) return res.status(400).json({ error: slotError });

      if (price === undefined || price === null) {
        return res
          .status(400)
          .json({ error: "Validation Error: 'price' is required" });
      }
      const parsedPrice = Number(price);
      if (isNaN(parsedPrice) || parsedPrice < 0) {
        return res
          .status(400)
          .json({
            error: "Validation Error: 'price' must be a valid positive number",
          });
      }
      let parsedStock = 0;
      if (stock !== undefined && stock !== null) {
        parsedStock = Number(stock);
        if (isNaN(parsedStock) || parsedStock < 0) {
          return res
            .status(400)
            .json({
              error:
                "Validation Error: 'stock' must be a valid positive integer",
            });
        }
      }
      const newProduct = {
        name: name.trim(),
        description: description ? description.trim() : "",
        price: parsedPrice, // Saved strictly as a Number for down-stream calculations
        stock: parsedStock, // Guaranteed to be a number (defaults to 0)
        image: image || null, // base64 data URL, or null if the owner skipped adding a photo
        slotNumber: parsedSlotNumber, // Which physical slot in the machine dispenses this item
        deviceId: deviceId, // Which physical machine this item is stocked in
        ownerId: req.user.id, // Securely injected from authentication middleware
        createdAt: new Date(),
      };

      const result = await client
        .db("dispo")
        .collection("products")
        .insertOne(newProduct);

      return res.status(201).json({
        _id: result.insertedId,
        ...newProduct,
      });
    } catch (error) {
      console.error("Error creating product:", error);
      return res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.put(
  "/api/products/:id",
  requireAuth,
  requireRole(["owner", "admin"]),
  async (req, res) => {
    try {
      const product = await productsCollection.findOne({ _id: new ObjectId(req.params.id) });
      if (!product) return res.status(404).json({ error: "Not found" });
      if (product.ownerId !== req.user.id && req.user.role !== "admin") {
        return res.status(403).json({ error: "Not your product" });
      }

      const update = { ...req.body };
      if (update.slotNumber !== undefined) {
        const parsedSlotNumber = Number(update.slotNumber);
        const targetDeviceId = update.deviceId || product.deviceId;
        const slotError = await validateSlot(targetDeviceId, parsedSlotNumber, product._id.toString());
        if (slotError) return res.status(400).json({ error: slotError });
        update.slotNumber = parsedSlotNumber;
      }

      await productsCollection.updateOne({ _id: product._id }, { $set: update });
      res.json({ success: true });
    } catch (error) {
      console.error("Error updating product:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
);

app.delete(
  "/api/products/:id",
  requireAuth,
  requireRole(["admin", "owner"]),
  async (req, res) => {
    try {
      const product = await productsCollection.findOne({_id: new ObjectId(req.params.id)})
      if (!product) return res.status(404).json({ error: "Not found" });
      if (product.ownerId !== req.user.id && req.user.role !== "admin") {
        return res.status(403).json({ error: "Not your product" });
      }
      await productsCollection.deleteOne({_id: product._id});
      res.json({success: true});
    } catch (error) {
      console.error("Error deleting product:", error);
      res.status(500).json({ error: "Internal server error" });
    }
  }
)

// ── Orders ──────────────────────────────────────────────────────
// Any logged-in customer can place an order. Payment is simulated (the
// TODO below is where a real Stripe sandbox integration would slot in),
// but the dispense lifecycle is real: every order starts "pending" and
// only becomes "completed" once the physical machine actually dispenses
// the item and confirms it. For now (no real ESP32 endpoint wired up
// yet), the owner can mark an order complete manually from /owner/orders —
// that's the same transition a real hardware callback would trigger later.
app.post("/api/orders", requireAuth, async (req, res) => {
  try {
    const { deviceId, items } = req.body;

    if (!deviceId) {
      return res.status(400).json({ error: "Validation Error: 'deviceId' is required" });
    }
    if (!Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: "Validation Error: cart is empty" });
    }

    const device = await devicesCollection.findOne({ _id: new ObjectId(deviceId) });
    if (!device) {
      return res.status(400).json({ error: "Validation Error: device not found" });
    }

    // Re-fetch every product server-side by (deviceId, slotNumber) — never
    // trust price/name/qty sent from the browser, and slotNumber is what
    // the physical machine actually needs to know what to dispense.
    const orderItems = [];
    let total = 0;

    for (const requested of items) {
      const slotNumber = Number(requested.slotNumber);
      if (!Number.isInteger(slotNumber) || !requested.qty || requested.qty < 1) {
        return res.status(400).json({ error: "Validation Error: each item needs a slotNumber and qty >= 1" });
      }
      const product = await productsCollection.findOne({ deviceId, slotNumber });
      if (!product) {
        return res.status(400).json({ error: `No product found in slot ${slotNumber} on this device` });
      }
      if (product.stock < requested.qty) {
        return res.status(400).json({ error: `Not enough stock for ${product.name} (only ${product.stock} left)` });
      }
      const lineTotal = product.price * requested.qty;
      total += lineTotal;
      orderItems.push({
        slotNumber,
        name: product.name, // locked in at time of purchase
        price: product.price, // locked in at time of purchase
        qty: requested.qty,
      });
    }

    // Decrement stock for each item. Not wrapped in a Mongo transaction
    // (would need a replica set) — acceptable for this project's scope,
    // worth flagging as a known simplification for a real production system.
    for (const item of orderItems) {
      await productsCollection.updateOne(
        { deviceId, slotNumber: item.slotNumber },
        { $inc: { stock: -item.qty } }
      );
    }

    const newOrder = {
      customerId: req.user.id,
      deviceId,
      items: orderItems,
      total,
      status: "pending", // becomes "completed" once the machine confirms dispensing
      createdAt: new Date(),
      completedAt: null,
    };
    const result = await ordersCollection.insertOne(newOrder);

    res.status(201).json({ _id: result.insertedId, ...newOrder });
  } catch (error) {
    console.error("Error creating order:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Current customer's own order history
app.get("/api/orders/mine", requireAuth, async (req, res) => {
  try {
    const orders = await ordersCollection
      .find({ customerId: req.user.id })
      .sort({ createdAt: -1 })
      .toArray();
    res.json(orders);
  } catch (error) {
    console.error("Error listing orders:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Owner sees orders across their own devices; admin sees every order.
// This is what powers the revenue/top-sellers charts AND /owner/orders.
app.get("/api/orders", requireAuth, requireRole(["owner", "admin"]), async (req, res) => {
  try {
    let filter = {};
    if (req.user.role !== "admin") {
      const ownDevices = await devicesCollection
        .find({ ownerId: req.user.id }, { projection: { _id: 1 } })
        .toArray();
      const deviceIds = ownDevices.map((d) => d._id.toString());
      filter = { deviceId: { $in: deviceIds } };
    }
    const orders = await ordersCollection.find(filter).sort({ createdAt: -1 }).toArray();
    res.json(orders);
  } catch (error) {
    console.error("Error listing all orders:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

// Manual "mark as dispensed" for now — this is exactly the transition a
// real ESP32 dispense-confirmation callback would trigger later; the data
// shape doesn't need to change when that gets built, only who calls this.
app.patch("/api/orders/:id/complete", requireAuth, requireRole(["owner", "admin"]), async (req, res) => {
  try {
    const order = await ordersCollection.findOne({ _id: new ObjectId(req.params.id) });
    if (!order) return res.status(404).json({ error: "Order not found" });

    if (req.user.role !== "admin") {
      const device = await devicesCollection.findOne({ _id: new ObjectId(order.deviceId) });
      if (!device || device.ownerId !== req.user.id) {
        return res.status(403).json({ error: "Not your order" });
      }
    }

    if (order.status === "completed") {
      return res.status(400).json({ error: "Order is already completed" });
    }

    await ordersCollection.updateOne(
      { _id: order._id },
      { $set: { status: "completed", completedAt: new Date() } }
    );
    res.json({ success: true });
  } catch (error) {
    console.error("Error completing order:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.get("/", (req, res) => {
  res.send("SERVER created");
});

// Only actually binds to a port for local dev (`node index.js` /
// `nodemon index.js`). On Vercel, the exported `app` below is what gets
// used directly as a serverless request handler — this listen() call
// simply never gets reached in that environment.
if (!process.env.VERCEL) {
  app.listen(port, () => {
    console.log(`server running at port: ${port}`);
  });
}

export default app;
